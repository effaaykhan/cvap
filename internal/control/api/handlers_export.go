package api

import (
	"context"
	"encoding/csv"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// CSV export — the reporting §2 permits ("CSV export only"), and the endpoint
// most likely to be pointed at a whole tenant's findings.
//
// ============================================================================
// It is bounded, and it REFUSES rather than truncates.
// ============================================================================
//
// A CSV that quietly stops at the cap is an incomplete export somebody treats as
// complete, and CSV has no in-band place to carry "there is more" that a
// spreadsheet reader will see. So the guarantee is stronger than a visible
// truncation marker: the export is either COMPLETE or refused with 422 and a
// message to narrow the filter. store.ListForExport asks for ExportRowCap+1;
// exceeding the cap means "more exist" and the file is never written.
//
// The tenant predicate is store.Read's, like every read here — an export with a
// missing tenant scope is the worst version of this endpoint, so it goes through
// the same door as everything else and never a raw query.

// csvSafe neutralises spreadsheet formula injection. A cell beginning with
// =, +, -, @, TAB or CR is treated as a formula by Excel and Google Sheets, so
// a derived value like a hostname of `=cmd|'/c calc'!A1` would execute when the
// export is opened. Prefixing a leading apostrophe forces the cell to be read as
// text; encoding/csv already handles commas, quotes and newlines inside a field,
// so this covers only the leading-character formula trigger.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

func (s *Server) exportFindingsCSV(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var f store.FindingListFilter
	f.Status = q.Get("status")
	if f.Status != "" && !validFindingStatuses[f.Status] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"status must be one of open, confirmed, false_positive, accepted_risk, remediated, closed.", nil)
		return
	}
	f.Severity = q.Get("severity")
	if f.Severity != "" && !validSeverities[f.Severity] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"severity must be one of info, low, medium, high, critical.", nil)
		return
	}
	if v := q.Get("asset_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "asset_id must be a uuid.", err)
			return
		}
		f.AssetID = id
	}

	rowCap := store.ExportRowCap
	if s.cfg.ExportRowCap > 0 {
		rowCap = s.cfg.ExportRowCap
	}

	tenant, _ := tenantFrom(r.Context())
	var rowsOut []store.FindingSummary
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		rowsOut, err = (store.Findings{}).ListForExport(ctx, c, f, rowCap+1)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	// More than the cap matched: refuse, rather than write a file that is
	// silently short of the truth. Unprocessable, not an internal error — the
	// caller can fix it by filtering.
	if len(rowsOut) > rowCap {
		writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
			"this export matches more than "+strconv.Itoa(rowCap)+
				" findings; narrow it with a status, severity, or asset filter.", nil)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	// A stable header row; the columns are the summary an analyst triages by.
	_ = cw.Write([]string{
		"finding_id", "rule", "category", "severity", "status",
		"asset_id", "asset_hostname", "instance_locator", "confidence",
		"exposure_zones", "first_seen", "last_seen",
	})
	for _, f := range rowsOut {
		// asset_hostname is DERIVED from what a scanned host volunteered — reverse
		// DNS, a certificate CN — so it is attacker-influenceable, and a value
		// beginning =, +, -, @ or a control character is a formula a spreadsheet
		// executes on open. csvSafe neutralises that; the rule name and locator
		// pass through it too, defensively, since a pack could carry either.
		_ = cw.Write([]string{
			f.ID.String(), csvSafe(f.RuleName), csvSafe(f.Category), f.Severity, f.Status,
			f.AssetID.String(), csvSafe(f.AssetHostname), csvSafe(f.Locator),
			strconv.FormatFloat(f.Confidence, 'f', 3, 64),
			strconv.Itoa(f.ExposureZones),
			f.FirstSeen.UTC().Format(time.RFC3339),
			f.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
	// A write error here has already sent 200 and some rows; it cannot be
	// reported to the client, so it is logged against the request id like every
	// other post-header failure in this package.
	if err := cw.Error(); err != nil {
		s.log.ErrorContext(r.Context(), "findings CSV export write failed after headers",
			slog.Any("error", err))
	}
}
