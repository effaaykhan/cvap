package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// Identity settings (ADR-100, B39's second slice): the sighting window as a
// tenant setting, tied to the scan cadence it has to accommodate rather than a
// constant. Two scans have to land inside one window for a key to become trust
// material (ADR-094), so a window shorter than twice the cadence is one no
// observed key ever satisfies — and the API refuses it with the cadence it
// measured, rather than letting an operator set a value that quietly turns the
// credentialed path off.

// IdentitySettingsResponse is the tenant's window beside what bounds it.
type IdentitySettingsResponse struct {
	SightingWindowHours int  `json:"sighting_window_hours" doc:"How long a sighting counts toward observed trust and an address is evidence of the same host."`
	IsDefault           bool `json:"is_default" doc:"True when no operator has set it; the value shown is the default."`
	DefaultHours        int  `json:"default_hours"`
	MinHours            int  `json:"min_hours"`
	MaxHours            int  `json:"max_hours"`
	// The measured scan cadence the window must accommodate: the median gap
	// between the tenant's recent completed scans. Absent with fewer than two.
	ScanCadenceHours   *float64 `json:"scan_cadence_hours,omitempty" doc:"Median hours between the last completed scans; a window under twice this is refused."`
	ScanCadenceSamples int      `json:"scan_cadence_samples" doc:"How many completed scans the cadence was measured over."`
}

// IdentitySettingsRequest sets the window.
type IdentitySettingsRequest struct {
	SightingWindowHours int    `json:"sighting_window_hours" doc:"Between min_hours and max_hours, and at least twice the measured scan cadence."`
	Reason              string `json:"reason" doc:"Why. Recorded in the audit log beside who changed it. At most 4 KiB."`
}

const cadenceSamples = 10

func (s *Server) identitySettings(w http.ResponseWriter, r *http.Request, c *store.Conn) (IdentitySettingsResponse, error) {
	ctx := r.Context()
	win, err := (store.IdentitySettings{}).Window(ctx, c)
	if err != nil {
		return IdentitySettingsResponse{}, err
	}
	isDefault, err := (store.IdentitySettings{}).IsDefault(ctx, c)
	if err != nil {
		return IdentitySettingsResponse{}, err
	}
	done, err := (store.Scans{}).RecentCompletions(ctx, c, cadenceSamples)
	if err != nil {
		return IdentitySettingsResponse{}, err
	}
	out := IdentitySettingsResponse{
		SightingWindowHours: int(win.Hours()), IsDefault: isDefault,
		DefaultHours: int(store.DefaultSightingWindow.Hours()), MinHours: int(store.MinSightingWindow.Hours()), MaxHours: int(store.MaxSightingWindow.Hours()),
		ScanCadenceSamples: len(done),
	}
	if gap, ok := domain.MedianGap(done); ok {
		h := gap.Hours()
		out.ScanCadenceHours = &h
	}
	return out, nil
}

func (s *Server) getIdentitySettings(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var out IdentitySettingsResponse
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		out, err = s.identitySettings(w, r, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func (s *Server) putIdentitySettings(w http.ResponseWriter, r *http.Request) {
	var req IdentitySettingsRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is required.", nil)
		return
	}
	if len(req.Reason) > maxReason {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is too long (4 KiB at most).", nil)
		return
	}
	// Bounded as an integer BEFORE it becomes a Duration: multiplied first, the
	// largest number an operator can type wraps to the shortest window
	// (measured: 5 124 120 hours stored as 24h25m).
	minH, maxH := int(store.MinSightingWindow.Hours()), int(store.MaxSightingWindow.Hours())
	if req.SightingWindowHours < minH || req.SightingWindowHours > maxH {
		writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
			fmt.Sprintf("sighting_window_hours must be between %d and %d.", minH, maxH), nil)
		return
	}
	want := time.Duration(req.SightingWindowHours) * time.Hour
	if want < store.MinSightingWindow || want > store.MaxSightingWindow {
		writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
			fmt.Sprintf("sighting_window_hours must be between %d and %d.", int(store.MinSightingWindow.Hours()), int(store.MaxSightingWindow.Hours())), nil)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	who := actor(r)
	now := time.Now().UTC()
	var before, after IdentitySettingsResponse
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		if before, err = s.identitySettings(w, r, c); err != nil {
			return err
		}
		// Twice the cadence: two scans must land inside one window (ADR-094).
		if before.ScanCadenceHours != nil && want < time.Duration(2*(*before.ScanCadenceHours)*float64(time.Hour)) {
			return errCadence
		}
		if err := (store.IdentitySettings{}).SetWindow(ctx, c, want, who, now); err != nil {
			return err
		}
		if after, err = s.identitySettings(w, r, c); err != nil {
			return err
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: who, ActorType: store.ActorUser,
			Action: "identity.window_changed", ResourceType: "tenant", ResourceID: nil,
			Detail: map[string]any{"from_hours": before.SightingWindowHours, "to_hours": after.SightingWindowHours,
				"reason": req.Reason, "scan_cadence_hours": before.ScanCadenceHours, "scan_cadence_samples": before.ScanCadenceSamples},
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, errCadence):
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
				fmt.Sprintf("A window of %d hours is under twice the measured scan cadence (%.1f hours over %d scans): no observed key could be seen by two scans inside it, and the credentialed path would never trust one. Scan more often, or set at least %d hours.",
					req.SightingWindowHours, *before.ScanCadenceHours, before.ScanCadenceSamples, int(2*(*before.ScanCadenceHours))+1), err)
		case errors.Is(err, store.ErrWindowOutOfBounds):
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable, err.Error(), err)
		default:
			storeError(w, r, s.log, err)
		}
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, after)
}

var errCadence = errors.New("api: sighting window under twice the scan cadence")
