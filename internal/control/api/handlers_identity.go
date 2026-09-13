package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/sshalgo"
	"github.com/effaaykhan/cvap/internal/store"
)

// The identity resolution queue's operator surface (ADR-097, B39).
//
// ADR-007: conflicting or insufficient evidence goes to the queue, and an
// operator adjudicates. ADR-094/096 route every address handover there and
// leave a rotated host's credentialed scans refusing until an operator
// confirms — a verb that did not exist. These three are the verbs. They
// verify nothing (B44: on banner data nothing can); they record a decision and
// who took it, which is the only verification an observed SSH key gets.

// IdentityQueueItemResponse is one parked (observation, key) pair.
type IdentityQueueItemResponse struct {
	ResolutionID  string  `json:"resolution_id"`
	ObservationID *string `json:"observation_id,omitempty" doc:"The observation that carried the key; absent once its partition has aged out (ADR-016). The evidence below is the copy."`
	KeyType       string  `json:"key_type" doc:"ssh_hostkey | service_cert_fp | ip_window (the address alone: a keyless observation parked with the group)."`
	KeyValue      string  `json:"key_value" doc:"The fingerprint, or the address for ip_window."`
	Source        string  `json:"source,omitempty" doc:"The service the key came from, port/protocol."`
	EnqueuedAt    string  `json:"enqueued_at"`
	Evidence      string  `json:"evidence,omitempty" doc:"What the service said, from the copied evidence: service, product and version — the banner the decision turns on."`
}

// IdentityQueueGroupResponse is everything pending at one address — the unit
// an operator decides on.
type IdentityQueueGroupResponse struct {
	Address        string                      `json:"address"`
	Candidates     []string                    `json:"candidates" doc:"The assets the evidence was judged against. Usually the address holder; empty when nothing held the address (two hosts answered on one port there)."`
	Reason         string                      `json:"reason" doc:"The latest verdict's reason, as domain.Resolve wrote it — including which continuity fact failed (ADR-096)."`
	FirstSeen      string                      `json:"first_seen"`
	LastSeen       string                      `json:"last_seen"`
	Items          []IdentityQueueItemResponse `json:"items" doc:"The newest items, at most 50; items_total is the full count."`
	ItemsTotal     int                         `json:"items_total"`
	Ambiguous      []AmbiguousServiceResponse  `json:"ambiguous" doc:"Services at the address where two or more different keys of one type were parked (two hosts answered on one port), computed over all items, not only the ones shown; the first 200, ambiguous_total beside them. Not computed (empty, total 0) when keys_total exceeds 200: such a group can only be discarded, so its choices would be unusable. Resolving needs one chosen value per entry (key_choices)."`
	AmbiguousTotal int                         `json:"ambiguous_total"`
	Keys           []ParkedKeyResponse         `json:"keys" doc:"The distinct parked keys at the address, over all items — what a decision records; the first 200, keys_total beside them."`
	KeysTotal      int                         `json:"keys_total"`
	Held           []HeldKeyResponse           `json:"held" doc:"What each candidate holds live on the contested services — what same_host retires."`
}

// ParkedKeyResponse is one distinct parked key with how many items carry it.
type ParkedKeyResponse struct {
	KeyType   string `json:"key_type"`
	Source    string `json:"source"`
	KeyValue  string `json:"key_value"`
	Items     int    `json:"items"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// HeldKeyResponse is a candidate's live key on a contested service.
type HeldKeyResponse struct {
	AssetID  string `json:"asset_id"`
	KeyType  string `json:"key_type"`
	Source   string `json:"source"`
	KeyValue string `json:"key_value"`
}

// AmbiguousServiceResponse is one service with several parked keys of one
// type; the operator names which value is the host.
type AmbiguousServiceResponse struct {
	KeyType     string   `json:"key_type"`
	Source      string   `json:"source"`
	Values      []string `json:"values" doc:"The first 200; values_total beside them."`
	ValuesTotal int      `json:"values_total"`
}

// IdentityQueueResponse is the pending queue, newest contest first.
type IdentityQueueResponse struct {
	Groups         []IdentityQueueGroupResponse `json:"groups" doc:"The newest 200 contested addresses, or the one named by ?address=."`
	AddressesTotal int64                        `json:"addresses_total" doc:"Every contested address, listed or not — an attacker's newer parks can push a real contest off the page; name it with ?address= to reach it."`
}

func (s *Server) listIdentityQueue(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	only := ""
	if v := r.URL.Query().Get("address"); v != "" {
		ip, err := netip.ParseAddr(v)
		if err != nil || ip.Zone() != "" {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "address must be a bare IP address.", err)
			return
		}
		only = ip.Unmap().String()
	}
	var groups []store.QueueGroup
	var total int64
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		if groups, err = (store.ResolutionQueue{}).ListPending(ctx, c, 200, only); err != nil {
			return err
		}
		total, err = (store.ResolutionQueue{}).PendingAddresses(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := IdentityQueueResponse{Groups: make([]IdentityQueueGroupResponse, 0, len(groups)), AddressesTotal: total}
	for _, g := range groups {
		gr := IdentityQueueGroupResponse{
			Address: g.Address, Reason: g.Reason,
			// Nanosecond precision, because last_seen comes back as seen_through
			// and is compared against enqueued_at: a second-truncated value
			// excluded the newest items from the decision it was rendered for.
			FirstSeen: g.FirstSeen.UTC().Format(time.RFC3339Nano), LastSeen: g.LastSeen.UTC().Format(time.RFC3339Nano),
			Candidates: make([]string, 0, len(g.Candidates)),
			Items:      make([]IdentityQueueItemResponse, 0, len(g.Items)),
			ItemsTotal: g.ItemsTotal,
			Ambiguous:  make([]AmbiguousServiceResponse, 0, len(g.Ambiguous)),
		}
		for _, a := range g.Ambiguous {
			gr.Ambiguous = append(gr.Ambiguous, AmbiguousServiceResponse{KeyType: string(a.KeyType), Source: a.Source, Values: a.Values, ValuesTotal: a.ValuesTotal})
		}
		gr.AmbiguousTotal = g.AmbiguousTotal
		gr.KeysTotal = g.KeysTotal
		gr.Keys = make([]ParkedKeyResponse, 0, len(g.Keys))
		for _, k := range g.Keys {
			gr.Keys = append(gr.Keys, ParkedKeyResponse{KeyType: string(k.KeyType), Source: k.Source, KeyValue: k.Value, Items: k.Items,
				FirstSeen: k.FirstSeen.UTC().Format(time.RFC3339), LastSeen: k.LastSeen.UTC().Format(time.RFC3339)})
		}
		gr.Held = make([]HeldKeyResponse, 0, len(g.Held))
		for _, h := range g.Held {
			gr.Held = append(gr.Held, HeldKeyResponse{AssetID: h.AssetID.String(), KeyType: string(h.KeyType), Source: h.Source, KeyValue: h.Value})
		}
		for _, id := range g.Candidates {
			gr.Candidates = append(gr.Candidates, id.String())
		}
		for _, it := range g.Items {
			ir := IdentityQueueItemResponse{
				ResolutionID: it.ResolutionID.String(), KeyType: string(it.KeyType), KeyValue: it.KeyValue,
				Source: it.Source, EnqueuedAt: it.EnqueuedAt.UTC().Format(time.RFC3339),
				Evidence: it.Evidence,
			}
			if it.ObservationID != nil {
				v := it.ObservationID.String()
				ir.ObservationID = &v
			}
			gr.Items = append(gr.Items, ir)
		}
		out.Groups = append(out.Groups, gr)
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// ResolveIdentityRequest is an operator's adjudication of one address.
type ResolveIdentityRequest struct {
	Address     string             `json:"address" doc:"The contested address, as the queue lists it."`
	Decision    string             `json:"decision" doc:"same_host: the parked keys belong to asset_id — its held key of the same service is retired and the parked one recorded as confirmed; the parked observations attach to it. different_host: the parked group is a host of its own — a new asset is created holding the parked keys and the address. discard: the group is noise — every item closes as discarded, nothing is recorded, nothing is trusted; the exit for a group too large or too hostile to decide key by key."`
	AssetID     string             `json:"asset_id,omitempty" doc:"Required for same_host: one of the group's candidates."`
	KeyChoices  []KeyChoiceRequest `json:"key_choices,omitempty" doc:"Which parked key is the host, one per ambiguous service (two different keys of one type parked from one service: two hosts answered on one port). Each names the service, because one fingerprint can be parked on two ports. The other keyed items of each named service close as discarded. Required for every ambiguous service in the group; ignored otherwise."`
	Reason      string             `json:"reason" doc:"Why. Recorded in the audit log beside who decided. At most 4 KiB."`
	SeenThrough string             `json:"seen_through" doc:"The listing's last_seen for this address, as rendered. The decision acts only on items parked by then; anything parked since stays pending and the address is listed again. Required: a key parked between the render and the click must not be confirmed unseen."`
}

// KeyChoiceRequest names the host's key on one service.
type KeyChoiceRequest struct {
	KeyType  string `json:"key_type"`
	Source   string `json:"source" doc:"port/protocol, as the listing's ambiguous entry gives it."`
	KeyValue string `json:"key_value"`
}

// maxReason bounds the free text an operator writes into the audit log.
const maxReason = 4096

// ResolveIdentityResponse is what the verb did.
type ResolveIdentityResponse struct {
	AssetID           string   `json:"asset_id" doc:"The asset the parked observations now belong to; empty for discard."`
	ItemsClosed       int64    `json:"items_closed"`
	KeysRecorded      []string `json:"keys_recorded"`
	KeysRetired       []string `json:"keys_retired"`
	KeysHeldElsewhere []string `json:"keys_held_elsewhere" doc:"Parked keys another asset holds live, left there: moving them is a merge of two assets (B40). Their items closed as discarded."`
	KeysDiscarded     []string `json:"keys_discarded" doc:"Parked keys the operator's choices rejected; their items closed as discarded."`
}

func (s *Server) resolveIdentity(w http.ResponseWriter, r *http.Request) {
	var req ResolveIdentityRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" || req.Address == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "address and reason are required.", nil)
		return
	}
	if len(req.Reason) > maxReason {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is too long (4 KiB at most).", nil)
		return
	}
	seenThrough, err := time.Parse(time.RFC3339Nano, req.SeenThrough)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "seen_through must be the listing's last_seen (RFC 3339).", err)
		return
	}
	// Nothing was rendered in the future: a later seen_through is not a
	// set the operator looked at, it is a bypass of the render→click
	// control (measured: 2099 acted on a key parked after the click).
	if seenThrough.After(time.Now().Add(5 * time.Second)) {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "seen_through is in the future; send the listing's last_seen.", nil)
		return
	}
	// The zero time parses and is not in the future — and means no bound
	// at all (measured: a key parked after the click recorded as confirmed).
	if seenThrough.IsZero() || seenThrough.Year() < 2000 {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "seen_through must be the listing's last_seen, not a zero time.", nil)
		return
	}
	if len(req.KeyChoices) > store.MaxKeysPerGroup {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "too many key_choices.", nil)
		return
	}
	// One spelling of the address, chosen here rather than inherited from
	// the store's cast: the audit row records what the decision applied to,
	// not what the operator typed (a mask or a leading zero both cast).
	ip, err := netip.ParseAddr(req.Address)
	if err != nil || ip.Zone() != "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "address must be a bare IP address.", err)
		return
	}
	address := ip.Unmap().String()
	var assetID uuid.UUID
	switch req.Decision {
	case "same_host":
		id, err := uuid.Parse(req.AssetID)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "asset_id is required for same_host and must be a uuid.", err)
			return
		}
		assetID = id
	case "different_host", "discard":
	default:
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "decision must be same_host, different_host or discard.", nil)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	who := actor(r)
	now := time.Now().UTC()
	var res store.Resolution
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		chosen := make([]store.KeyChoice, 0, len(req.KeyChoices))
		for _, ch := range req.KeyChoices {
			chosen = append(chosen, store.KeyChoice{Type: domain.IdentityKeyType(ch.KeyType), Source: ch.Source, Value: ch.KeyValue})
		}
		switch req.Decision {
		case "same_host":
			res, err = (store.ResolutionQueue{}).ResolveSameHost(ctx, c, address, assetID, chosen, seenThrough, who, now)
		case "different_host":
			res, err = (store.ResolutionQueue{}).ResolveNewAsset(ctx, c, address, chosen, seenThrough, who, now)
		default:
			var n int64
			n, err = (store.ResolutionQueue{}).Discard(ctx, c, address, seenThrough, who, now)
			res = store.Resolution{ItemsClosed: n}
		}
		if err != nil {
			return err
		}
		// The decision and the decider, in the same transaction as the
		// decision (a refusal that rolls back its own record is the shape
		// internal/store/CLAUDE.md names; this is the other way round — a
		// decision whose record could not be written is not made).
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: who, ActorType: store.ActorUser,
			Action: "identity.resolved", ResourceType: "asset", ResourceID: resourceOrNil(res.AssetID),
			Detail: map[string]any{
				"address": address, "decision": req.Decision, "reason": req.Reason, "keys_chosen": req.KeyChoices, "seen_through": req.SeenThrough,
				"items_closed": res.ItemsClosed, "keys_recorded": res.KeysRecorded, "keys_retired": res.KeysRetired,
				"keys_held_elsewhere": orEmpty(res.KeysHeldElsewhere), "keys_discarded": orEmpty(res.KeysDiscarded),
				"note": "an operator's decision; nothing here verifies the host holds the key (B44)",
			},
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNothingPending):
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"Nothing is pending at that address for that asset; the queue moved.", err)
		case errors.Is(err, store.ErrAmbiguousGroup):
			msg := "Two different keys from one service are parked at that address (two hosts answered on one port); name which one is the host for every such service with key_choices."
			// Which service, in the refusal itself. The listing carries
			// `ambiguous` and the console reads it; an API caller sees only
			// this, and "some service" sends them back to the listing to work
			// out what the store already knew. Bounded: the names are the
			// stored service column, and a pre-0046 row's protocol is text a
			// scan point wrote.
			var amb *store.AmbiguousServiceError
			if errors.As(err, &amb) && len(amb.Services) > 0 {
				msg += " Unsettled: " + nameList(amb.Services, 8) + "."
			}
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable, msg, err)
		case errors.Is(err, store.ErrKeyNotParked):
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
				"A key_choices entry names a key that is not parked on that service at that address.", err)
		case errors.Is(err, store.ErrNothingToRecord):
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
				"different_host would record no key on the new asset (every parked key is another asset's, or the group is address-only); use same_host on the holder, or discard.", err)
		case errors.Is(err, store.ErrTooManyKeys):
			writeError(w, r, s.log, http.StatusUnprocessableEntity, CodeUnprocessable,
				"More distinct keys are parked at that address than a decision can cover; a decision covers exactly what the listing shows. Discard the group, or wait for the contest to expire.", err)
		default:
			storeError(w, r, s.log, err)
		}
		return
	}
	assetOut := ""
	if res.AssetID != uuid.Nil {
		assetOut = res.AssetID.String()
	}
	writeJSON(w, r, s.log, http.StatusOK, ResolveIdentityResponse{
		AssetID: assetOut, ItemsClosed: res.ItemsClosed,
		KeysRecorded: orEmpty(res.KeysRecorded), KeysRetired: orEmpty(res.KeysRetired),
		KeysHeldElsewhere: orEmpty(res.KeysHeldElsewhere), KeysDiscarded: orEmpty(res.KeysDiscarded),
	})
}

// ConfirmIdentityRequest is an operator's word on a rotation or a lapse.
type ConfirmIdentityRequest struct {
	Keys   []string `json:"keys" doc:"The keys the operator is confirming, as 'key_type fingerprint' — each a live rotated or lapsed key on the asset. Named keys only: the others stay excluded. A named key that is not rotated or lapsed (confirmed already, retired, never there) refuses the whole request (409)."`
	Reason string   `json:"reason" doc:"Why the operator believes these keys are the host's own. Recorded beside who decided. At most 4 KiB."`
}

// ConfirmIdentityResponse names the keys confirmed and the ones left waiting.
type ConfirmIdentityResponse struct {
	AssetID            string   `json:"asset_id"`
	KeysConfirmed      []string `json:"keys_confirmed" doc:"type and fingerprint of each key re-stamped confirmed."`
	KeysRemaining      []string `json:"keys_remaining" doc:"Rotated or lapsed keys still on the asset after this decision — not named, so not confirmed. At most 200; keys_remaining_total is how many there are."`
	KeysRemainingTotal int      `json:"keys_remaining_total" doc:"How many rotated or lapsed keys are still on the asset, listed above or not."`
}

func (s *Server) confirmIdentity(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "asset_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "asset_id is not a uuid.", err)
		return
	}
	var req ConfirmIdentityRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" || len(req.Keys) == 0 {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "keys and reason are required.", nil)
		return
	}
	if len(req.Reason) > maxReason {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is too long (4 KiB at most).", nil)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	who := actor(r)
	var keys, remaining []string
	var remainingTotal int
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Assets{}).GetByID(ctx, c, id); err != nil {
			return err
		}
		var err error
		keys, remaining, remainingTotal, err = (store.AssetIdentityKeys{}).Confirm(ctx, c, id, req.Keys)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return store.ErrNothingPending
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: who, ActorType: store.ActorUser,
			Action: "identity.confirmed", ResourceType: "asset", ResourceID: &id,
			Detail: map[string]any{
				"reason": req.Reason, "keys": keys, "keys_remaining": orEmpty(remaining), "keys_remaining_total": remainingTotal,
				"note": "the keys are credentialed trust material on ADR-094's terms from here; an operator's word, not a verification (B44)",
			},
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNothingPending):
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"That asset holds no rotated or lapsed key to confirm.", err)
		case errors.Is(err, store.ErrKeysChanged):
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"A named key is not a rotated or lapsed key on the asset any more; reload the page and look again.", err)
		default:
			storeError(w, r, s.log, err)
		}
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, ConfirmIdentityResponse{AssetID: id.String(), KeysConfirmed: keys,
		KeysRemaining: orEmpty(remaining), KeysRemainingTotal: remainingTotal})
}

// nameList joins at most n names for a refusal message, each bounded, with a
// count of what it left out: an error body is not a listing.
func nameList(names []string, n int) string {
	out := make([]string, 0, n)
	for _, s := range names[:min(n, len(names))] {
		if len(s) > 48 {
			s = s[:48] + "…"
		}
		out = append(out, s)
	}
	j := strings.Join(out, ", ")
	if len(names) > n {
		j += fmt.Sprintf(" and %d more", len(names)-n)
	}
	return j
}

func resourceOrNil(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// IdentityKeyResponse is one live identity key on an asset with what the
// credentialed engine would make of it right now (B39: "sightings needed").
type IdentityKeyResponse struct {
	KeyType       string  `json:"key_type"`
	Fingerprint   string  `json:"fingerprint"`
	Source        string  `json:"source,omitempty" doc:"The service the key came from, port/protocol."`
	Provenance    string  `json:"provenance" doc:"Which verdict recorded it (merge, new_asset, attach), or rotation / lapsed (excluded from trust until confirmed), confirmed (an operator's word), unknown (before ADR-094)."`
	Address       string  `json:"address,omitempty" doc:"Where it was sighted; absent when never sighted at an address."`
	Port          int     `json:"port,omitempty" doc:"The port it was sighted on; the credentialed engine dials 22."`
	AddressHeld   bool    `json:"address_held" doc:"Whether the asset holds the sighting's address live right now. A sighting at an address the asset lost is history, not trust."`
	ScansSeen     int     `json:"scans_seen" doc:"Distinct scans that saw it there inside the window (ADR-094)."`
	LastSeenAt    *string `json:"last_seen_at,omitempty"`
	TrustMaterial bool    `json:"trust_material" doc:"Whether the credentialed engine would trust this key for its dial (port 22) at this address right now — the trust root's own predicate (SSHHostKeyFingerprintsAt), so the page and the wire cannot disagree."`
	Note          string  `json:"note" doc:"Why it is or is not trust material, in words: sightings still needed, or the operator confirmation that would unlock it."`
}

func identityKeyResponses(keys []store.KeySighting, now time.Time) []IdentityKeyResponse {
	out := make([]IdentityKeyResponse, 0, len(keys))
	for _, k := range keys {
		r := IdentityKeyResponse{
			KeyType: string(k.Type), Fingerprint: k.Value, Source: k.Source, Provenance: string(k.Provenance),
			Address: k.Address, Port: k.Port, AddressHeld: k.AddressHeld, ScansSeen: k.ScansSeen,
			TrustMaterial: k.TrustMaterial(now, store.SightingWindow, sshalgo.DefaultPort),
		}
		if k.LastSeenAt != nil {
			v := k.LastSeenAt.UTC().Format(time.RFC3339)
			r.LastSeenAt = &v
		}
		r.Note = trustNote(k, now)
		out = append(out, r)
	}
	return out
}

// trustNote is the sentence beside a key on the asset page.
func trustNote(k store.KeySighting, now time.Time) string {
	switch {
	case k.Provenance == store.KeyFromRotation:
		return "recorded by a key rotation; excluded from credentialed trust and from corroborating a renewal until an operator confirms it"
	case k.Provenance == store.KeyFromLapsed:
		return "recorded when the previous holder lapsed; excluded from credentialed trust and from corroborating a renewal until an operator confirms it"
	case k.Type != "ssh_hostkey":
		return "identity evidence only; not credentialed trust material"
	case k.Address == "":
		return "never sighted at an address; two sightings at the address are needed"
	case !k.AddressHeld:
		return "sighted at an address the asset no longer holds; history, not trust"
	case k.Port != sshalgo.DefaultPort:
		return "sighted on a port the credentialed engine does not dial"
	case k.ScansSeen < 2:
		return "one more sighting at this address is needed (ADR-094)"
	case k.LastSeenAt == nil || k.LastSeenAt.Before(now.Add(-store.SightingWindow)):
		return "last sighting is outside the window; two sightings inside it are needed"
	}
	return "credentialed trust material at this address (two sightings inside the window; an echo, not a proof — B44)"
}
