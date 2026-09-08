package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The asset read surface (session 18). Reads only — assets are DERIVED from
// observations (ADR-006) and nothing here writes one.

// AssetSummary is one row of the asset inventory.
type AssetSummary struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname" doc:"Primary hostname, or empty if the asset has only addresses."`
	OSFamily    string    `json:"os_family"`
	DeviceType  string    `json:"device_type"`
	Criticality string    `json:"criticality"`
	Environment string    `json:"environment" doc:"Operator-set environment tag. Empty is treated as production by the rules (the safe default)."`
	Fragile     bool      `json:"fragile" doc:"Rate-capped and probe-suppressed regardless of policy (ADR-024)."`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// AssetListResponse is a keyset page of assets, newest-seen first.
type AssetListResponse struct {
	Assets     []AssetSummary `json:"assets"`
	NextBefore *string        `json:"next_before,omitempty" doc:"Cursor for the next page; pass as before with next_id. Absent on the last page."`
	NextID     *string        `json:"next_id,omitempty"`
}

// AssetAddressResponse is one current address of an asset.
type AssetAddressResponse struct {
	IP        string    `json:"ip,omitempty"`
	MAC       string    `json:"mac,omitempty"`
	ValidFrom time.Time `json:"valid_from" doc:"When this address was first observed on the asset. Current addresses only; history is not returned."`
}

// AssetServiceResponse is one listening endpoint on an asset.
type AssetServiceResponse struct {
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	Service    string    `json:"service,omitempty"`
	Product    string    `json:"product,omitempty"`
	Version    string    `json:"version,omitempty"`
	Confidence *float64  `json:"version_confidence,omitempty" doc:"Confidence in the version, when it was inferred rather than read authoritatively. Absent means no version or no confidence recorded."`
	Method     string    `json:"method,omitempty" doc:"How the identification was learned: banner (volunteered on connect), probe (solicited), tls, none. The provenance behind 'Apache 2.2.8 (banner)'."`
	LastSeen   time.Time `json:"last_seen"`
}

// AssetResponse is the full asset detail.
type AssetResponse struct {
	AssetSummary
	OSVersion    string                 `json:"os_version,omitempty"`
	Vendor       string                 `json:"vendor,omitempty"`
	Owner        string                 `json:"owner,omitempty"`
	Addresses    []AssetAddressResponse `json:"addresses"`
	Services     []AssetServiceResponse `json:"services"`
	OpenFindings int                    `json:"open_findings" doc:"Count of open or confirmed findings on this asset."`

	// OS attribution (ADR-061), the three-state model made visible:
	//   - distro_family absent            -> no attribution
	//   - distro_family present, release absent -> FAMILY-ONLY (Ubuntu, no feed;
	//     a credentialed-follow-up candidate, unmatched for advisories)
	//   - both present                    -> resolved
	// os_provenance is which services contributed, agreed and were ignored — the
	// claim's evidence, so a wrong attribution can be understood on screen.
	DistroFamily  string          `json:"distro_family,omitempty" doc:"Distribution family from banners (ubuntu, debian, windows). Absent means no OS attribution."`
	DistroRelease *string         `json:"distro_release,omitempty" doc:"Distro release (ubuntu2204) — the advisory-feed key. Absent with a family present is FAMILY-ONLY: known distribution, no release, unmatched for advisories (ADR-014). Banners never carry it; resolving it is knowledge-pipeline work."`
	OSConfidence  *float64        `json:"os_confidence,omitempty" doc:"Confidence in the attribution. Non-authoritative — derived from banners, never OS detection."`
	OSProvenance  json.RawMessage `json:"os_provenance,omitempty" doc:"Which services contributed, agreed and were ignored, with the family each suggested."`
}

func assetSummary(a *store.Asset) AssetSummary {
	return AssetSummary{
		ID: a.ID.String(), Hostname: a.Hostname, OSFamily: a.OSFamily,
		DeviceType: a.DeviceType, Criticality: string(a.Criticality),
		Environment: a.Environment, Fragile: a.Fragile,
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen,
	}
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var filter store.AssetFilter
	filter.Query = q.Get("q")
	filter.Environment = q.Get("environment")
	if v := q.Get("fragile"); v != "" {
		switch v {
		case "true":
			t := true
			filter.Fragile = &t
		case "false":
			f := false
			filter.Fragile = &f
		default:
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"fragile must be true or false.", nil)
			return
		}
	}

	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := atoiBounded(v, 1, 200)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"limit must be an integer between 1 and 200.", err)
			return
		}
		limit = n
	}

	before, beforeID, ok := s.keysetCursor(w, r)
	if !ok {
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var page *store.AssetPage
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		page, err = (store.Assets{}).List(ctx, c, filter, before, beforeID, limit)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	out := AssetListResponse{Assets: make([]AssetSummary, 0, len(page.Assets))}
	for i := range page.Assets {
		out.Assets = append(out.Assets, assetSummary(&page.Assets[i]))
	}
	setKeysetNext(&out.NextBefore, &out.NextID, page.NextBefore, page.NextID)
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "asset_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "asset_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	var d *store.AssetDetail
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		d, err = (store.Assets{}).GetDetail(ctx, c, id)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	out := AssetResponse{
		AssetSummary: assetSummary(&d.Asset),
		OSVersion:    d.OSVersion, Vendor: d.Vendor, Owner: d.Owner,
		Addresses:    make([]AssetAddressResponse, 0, len(d.Addresses)),
		Services:     make([]AssetServiceResponse, 0, len(d.Services)),
		OpenFindings: d.OpenFindings,
		DistroFamily: d.DistroFamily, DistroRelease: d.DistroRelease,
		OSConfidence: d.OSConfidence, OSProvenance: d.OSProvenance,
	}
	for _, a := range d.Addresses {
		out.Addresses = append(out.Addresses, AssetAddressResponse{IP: a.IP, MAC: a.MAC, ValidFrom: a.ValidFrom})
	}
	for _, sv := range d.Services {
		out.Services = append(out.Services, AssetServiceResponse{
			Port: sv.Port, Protocol: sv.Protocol, Service: sv.Service,
			Product: sv.Product, Version: sv.Version, Confidence: sv.Confidence,
			Method: sv.Method, LastSeen: sv.LastSeen,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// keysetCursor parses the shared (before, before_id) cursor. Both halves or
// neither — one alone pages from a point the caller does not expect (the same
// rule listScans states). A zero time means no cursor, which the store reads as
// "first page".
func (s *Server) keysetCursor(w http.ResponseWriter, r *http.Request) (time.Time, uuid.UUID, bool) {
	q := r.URL.Query()
	v := q.Get("before")
	if v == "" {
		return time.Time{}, uuid.Nil, true
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"before must be an RFC 3339 timestamp.", err)
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.Parse(q.Get("before_id"))
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"before requires before_id, and it must be a uuid.", err)
		return time.Time{}, uuid.Nil, false
	}
	return t, id, true
}

func setKeysetNext(nextBefore **string, nextID **string, before time.Time, id uuid.UUID) {
	if before.IsZero() {
		return
	}
	b := before.Format(time.RFC3339Nano)
	i := id.String()
	*nextBefore, *nextID = &b, &i
}
