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

	// CodeTimeout is the bound firing, not a fault (ADR-101). Separate from
	// CodeInternal because they ask the operator for different things: an
	// internal error is a bug report, a timeout is a query that needs
	// profiling, and an alert that cannot tell them apart pages the wrong
	// person.
	CodeTimeout = "timeout"

	// CodeCapacity is the deployment being out of connections, not a slow
	// query. Separate from CodeTimeout for the same reason CodeTimeout is
	// separate from CodeInternal: they send the operator to different places —
	// add capacity, versus profile a statement (ADR-102).
	CodeCapacity = "capacity"
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
func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	log := s.log
	switch {
	case errors.Is(err, store.ErrSessionInvalid), errors.Is(err, store.ErrCredentialLocked):
		// Client conditions, not ours. Without this they fell to the default and
		// were reported as a 500, which tells an operator their deployment is
		// broken when their account is simply locked.
		writeError(w, r, log, http.StatusUnauthorized, CodeUnauthorized,
			"Those credentials are not valid.", err)
	case errors.Is(err, store.ErrPoolExhausted):
		// 503, and NOT metered as a query timeout: the statement never ran, and
		// the cause is usually load belonging to another tenant.
		writeError(w, r, log, http.StatusServiceUnavailable, CodeCapacity,
			"The server is at capacity. Try again shortly.", err)
	case errors.Is(err, store.ErrStatementTimeout):
		// 504, not 500: the request was well formed and the server simply did
		// not finish it inside the budget. writeError logs this at Error with
		// the request id, which is the only handle an operator has to find the
		// statement afterwards.
		//
		// Not retryable, and the message says so rather than inviting a retry
		// that runs the same plan and spends the budget again.
		// Metered before the response is written, so Health can say the bound
		// fired without an operator having to find it in the log.
		if tenant, ok := tenantFrom(r.Context()); ok {
			s.timeouts.note(tenant, authenticatedFrom(r.Context()))
		}
		writeError(w, r, log, http.StatusGatewayTimeout, CodeTimeout,
			"The server did not finish this request within its time budget.", err)
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

// internalError is the flat-500 path, with the one exception the budget earns.
//
// Some handlers deliberately do NOT call storeError: on the login and OIDC
// surfaces its ErrNotFound -> 404 would be a user-existence oracle, so every
// fault there collapses to one indistinguishable 500. That is right for faults
// that could carry a signal about the subject, and wrong for a budget timeout,
// which is a property of how long a statement took and says nothing about who
// asked (ADR-101).
//
// A helper rather than a branch repeated at a dozen call sites, because the
// review that found this found it at TWO of them — the session Touch that runs
// on every authenticated request, and the whole OIDC flow — after the first was
// fixed by hand. A per-call-site branch is one somebody adds a thirteenth site
// without.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrStatementTimeout) || errors.Is(err, store.ErrPoolExhausted) {
		s.storeError(w, r, err)
		return
	}
	writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
		"An unexpected error occurred.", err)
}

func writeJSON(w http.ResponseWriter, r *http.Request, log *slog.Logger, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The class-of-response security headers (nosniff, X-Frame-Options,
	// Referrer-Policy, HSTS, CSP) are set once for every path by the
	// securityHeaders middleware (middleware.go), not here — a per-write helper
	// cannot cover the static SPA path, which does not call writeJSON. Only the
	// response-specific headers stay here: the JSON content type, and:
	//
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
