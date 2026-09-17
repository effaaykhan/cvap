package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/effaaykhan/cvap/internal/hostkeytrust"
	"github.com/effaaykhan/cvap/internal/store"
)

// Credential profiles (ADR-100, B39's second slice): the non-secret face of a
// profile, and the operator pin — the one trust root that outranks what
// discovery observed (ADR-091 §4). Until now known_hosts had a reader and no
// writer in the API or CLI, so a rotated host's only remedy was a confirm.

// CredentialProfileResponse never carries the secret or its pointer.
type CredentialProfileResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CredType  string    `json:"cred_type"`
	Username  string    `json:"username,omitempty"`
	PinLines  int       `json:"pin_lines" doc:"known_hosts lines an operator pinned; 0 means the fleet path uses the key CVAP observed for the target."`
	UpdatedAt time.Time `json:"updated_at"`
}

// CredentialProfileListResponse lists the tenant's profiles.
type CredentialProfileListResponse struct {
	Profiles []CredentialProfileResponse `json:"profiles"`
}

// PinKnownHostsRequest is the operator's pin.
type PinKnownHostsRequest struct {
	KnownHosts string `json:"known_hosts" doc:"Plain known_hosts lines — host[,host] keytype base64 — one per line; comments allowed, markers and hashed hosts refused. At most 64 KiB / 1000 lines."`
	Reason     string `json:"reason" doc:"Why. Recorded in the audit log beside who pinned. At most 4 KiB."`
}

// ClearPinRequest clears the pin.
type ClearPinRequest struct {
	Reason string `json:"reason" doc:"Why. Recorded in the audit log. At most 4 KiB."`
}

// PinKnownHostsResponse names what was pinned.
type PinKnownHostsResponse struct {
	ProfileID    string   `json:"profile_id"`
	Lines        int      `json:"lines"`
	Fingerprints []string `json:"fingerprints" doc:"SHA256 fingerprints of the pinned keys — public material, recorded in the audit event too."`
}

func (s *Server) listCredentialProfiles(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var profiles []store.CredentialProfileSummary
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		profiles, err = (store.CredentialProfiles{}).List(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := CredentialProfileListResponse{Profiles: make([]CredentialProfileResponse, 0, len(profiles))}
	for _, p := range profiles {
		out.Profiles = append(out.Profiles, CredentialProfileResponse{ID: p.ID.String(), Name: p.Name, CredType: p.CredType, Username: p.Username, PinLines: p.PinLines, UpdatedAt: p.UpdatedAt})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func (s *Server) pinKnownHosts(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "profile_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "profile_id is not a uuid.", err)
		return
	}
	var req PinKnownHostsRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" || len(req.Reason) > maxReason {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is required (4 KiB at most).", nil)
		return
	}
	material, fps, err := hostkeytrust.ValidatePin(req.KnownHosts)
	if err != nil {
		writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable, "known_hosts is not a pin this build accepts: "+err.Error(), err)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	who := actor(r)
	now := time.Now().UTC()
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.CredentialProfiles{}).SetKnownHosts(ctx, c, id, material, now); err != nil {
			return err
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: who, ActorType: store.ActorUser,
			Action: "credential.pinned", ResourceType: "credential_profile", ResourceID: &id,
			Detail: map[string]any{"reason": req.Reason, "lines": len(fps), "fingerprints": fps,
				"note": "an operator pin outranks the observed key for every host it names (ADR-091 §4); this is a trust decision, not a verification"},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, PinKnownHostsResponse{ProfileID: id.String(), Lines: len(fps), Fingerprints: fps})
}

func (s *Server) clearKnownHosts(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "profile_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "profile_id is not a uuid.", err)
		return
	}
	var req ClearPinRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" || len(req.Reason) > maxReason {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is required (4 KiB at most).", nil)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	who := actor(r)
	now := time.Now().UTC()
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		p, err := (store.CredentialProfiles{}).List(ctx, c)
		if err != nil {
			return err
		}
		had := -1
		for _, x := range p {
			if x.ID == id {
				had = x.PinLines
			}
		}
		if had < 0 {
			return store.ErrNotFound
		}
		if had == 0 {
			return errNoPin
		}
		if err := (store.CredentialProfiles{}).SetKnownHosts(ctx, c, id, "", now); err != nil {
			return err
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: who, ActorType: store.ActorUser,
			Action: "credential.pin_cleared", ResourceType: "credential_profile", ResourceID: &id,
			Detail: map[string]any{"reason": req.Reason, "lines_cleared": had,
				"note": "the fleet path uses the observed key for this profile's targets again (two sightings at the address, ADR-094)"},
		})
	})
	if err != nil {
		if errors.Is(err, errNoPin) {
			writeError(w, r, s.log, http.StatusConflict, CodeConflict, "That profile carries no pin to clear.", err)
			return
		}
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, CredentialProfileResponse{ID: id.String(), PinLines: 0, UpdatedAt: now})
}

var errNoPin = errors.New("api: no pin on the profile")
