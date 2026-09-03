package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/effaaykhan/cvap/internal/store"
)

// ErrorBody is the only error shape this API returns.
//
// ============================================================================
// It never carries a store error, and never describes the schema.
// ============================================================================
//
// internal/store/CLAUDE.md wrote this rule down while the constraint was being
// created rather than leaving it to be remembered when the API landed:
//
//	mapError embeds pgErr.ConstraintName, pgErr.ColumnName and pgErr.Message.
//	That is deliberate and useful at this layer [...] Every one of them is also
//	a schema fact. The API layer must not return these verbatim.
//
// So the mapping is one way and lossy on purpose: a sentinel becomes a status
// and a fixed sentence, and the detail goes to the log against the request id.
// An operator who needs the detail asks for it with the id, which is a path that
// goes through somebody with access to the logs.
type ErrorBody struct {
	// Error is a stable machine-readable code. Clients switch on this; the
	// message is for humans and may change.
	Error string `json:"error" doc:"Stable machine-readable code."`

	// Message is a fixed sentence per code. It never interpolates anything from
	// the failure, which is what keeps a constraint name out of it.
	Message string `json:"message" doc:"Human-readable explanation. Fixed per code."`

	// RequestID correlates this response with Core's log.
	RequestID string `json:"request_id" doc:"Correlates with Core's log for this request."`
}

// The codes. Stable, and a closed set.
const (
	CodeBadRequest    = "bad_request"
	CodeUnauthorized  = "unauthorized"
	CodeForbidden     = "forbidden"
	CodeNotFound      = "not_found"
	CodeConflict      = "conflict"
	CodeUnprocessable = "unprocessable"
	CodeInternal      = "internal"
)

// writeError sends an error response and logs the real one.
//
// The log gets the wrapped error; the client gets a code and a sentence. Both
// carry the request id, which is the only thing that joins them.
func writeError(w http.ResponseWriter, r *http.Request, log *slog.Logger, status int, code, message string, cause error) {
	id := requestIDFrom(r.Context())

	lg := log.With("request_id", id, "status", status, "code", code,
		"method", r.Method, "path", r.URL.Path)
	if cause != nil && status >= 500 {
		lg.Error("request failed", "err", cause)
	} else if cause != nil {
		lg.Info("request refused", "err", cause)
	} else {
		lg.Info("request refused")
	}

	writeJSON(w, r, log, status, ErrorBody{Error: code, Message: message, RequestID: id})
}

// storeError maps a store sentinel to a response.
//
// ErrNotFound covers both "no such row" and "belongs to another tenant", which
// under RLS are the same answer — so this produces 404 for both, and that is the
// point rather than an accident: an error that distinguished them would be a
// cross-tenant oracle.
//
// Anything unrecognised is a 500. Deliberately not a "best effort" guess: an
// unmapped store error is a case nobody thought about, and reporting it as a
// client error tells the caller to fix something that is not theirs.
func storeError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, store.ErrSessionInvalid), errors.Is(err, store.ErrCredentialLocked):
		// Client conditions, not ours. Without this they fell to the default and
		// were reported as a 500, which tells an operator their deployment is
		// broken when their account is simply locked.
		writeError(w, r, log, http.StatusUnauthorized, CodeUnauthorized,
			"Those credentials are not valid.", err)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, log, http.StatusNotFound, CodeNotFound,
			"No such resource.", err)
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, log, http.StatusConflict, CodeConflict,
			"That resource already exists.", err)
	case errors.Is(err, store.ErrForeignKey), errors.Is(err, store.ErrCheckViolation):
		writeError(w, r, log, http.StatusUnprocessableEntity, CodeUnprocessable,
			"The request refers to something that does not exist, or violates a constraint.", err)
	case errors.Is(err, store.ErrTenantIsolation):
		// A cross-tenant write attempt. 404, like every other cross-tenant
		// answer, and logged loudly: internal/store/CLAUDE.md calls this a
		// security event worth alerting on, which is why it is not folded in
		// with ErrNotPermitted above it.
		log.Error("RLS refused an operation — a cross-tenant write was attempted",
			"request_id", requestIDFrom(r.Context()), "err", err,
			"method", r.Method, "path", r.URL.Path)
		writeError(w, r, log, http.StatusNotFound, CodeNotFound, "No such resource.", err)
	default:
		writeError(w, r, log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
	}
}

func writeJSON(w http.ResponseWriter, r *http.Request, log *slog.Logger, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Response headers every answer carries.
	//
	// nosniff, because a JSON body that a browser decides to treat as HTML is a
	// stored-XSS vector out of any field an operator can set — a scan name, a
	// policy name. X-Frame-Options, because nothing here should ever be framed
	// and the kill switch in particular must not be clickjackable. HSTS,
	// because the session cookie is a bearer credential and the first plaintext
	// request is the one that leaks it.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	// Nothing this API returns should be cached: every response is
	// tenant-scoped and most are session-scoped, and a shared cache holding one
	// is a cross-tenant disclosure delivered by infrastructure.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status is already written, so this cannot become an error
		// response. Logged and dropped.
		log.Warn("failed to write response body",
			"request_id", requestIDFrom(r.Context()), "err", err)
	}
}
