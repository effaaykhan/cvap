package api

import (
	"context"
	"net/http"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// The open-ports surface (ADR-103).
//
// Before this, a discovery scan produced assets an operator could see and know
// nothing about: the ports were in `observations`, which is ephemeral, and the
// console had no route to them at all.

// OpenPortResponse is one listening endpoint as the overview renders it.
type OpenPortResponse struct {
	AssetID  string `json:"asset_id"`
	Address  string `json:"address,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`

	Identified bool      `json:"identified" doc:"False when discovery merely SAW the port answer and nothing identified what is listening (identification_method 'discovery', ADR-103). A console must render these as 'open, unidentified' rather than implying a service was recognised."`
	LastSeen   time.Time `json:"last_seen"`
}

// OpenPortsResponse is the tenant's listening endpoints, most recently seen
// first.
type OpenPortsResponse struct {
	Ports []OpenPortResponse `json:"ports"`

	// Truncated says the cap was reached, so the screen can say "showing the
	// most recent N" instead of implying this is the estate. A list that
	// silently stops is the same defect the CSV exports refuse outright
	// (ADR-052); here the page is bounded by design, so it is announced.
	Truncated bool `json:"truncated"`
	Limit     int  `json:"limit"`
}

// openPortsCap bounds the screen's read.
//
// Not an export: this feeds a table an operator scans with their eyes, and an
// unbounded read of every service on a large estate would spend the 30 s
// operator budget (ADR-101) to render something nobody can read. The CSV export
// is the path for the whole set.
const openPortsCap = 500

func (s *Server) openPorts(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())

	var rows []store.OpenPort
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		// One more than the cap, so "there is more" is measured rather than
		// guessed from a full page.
		rows, err = (store.Services{}).OpenPorts(ctx, c, openPortsCap+1)
		return err
	}); err != nil {
		s.storeError(w, r, err)
		return
	}

	out := OpenPortsResponse{Ports: []OpenPortResponse{}, Limit: openPortsCap}
	if len(rows) > openPortsCap {
		out.Truncated = true
		rows = rows[:openPortsCap]
	}
	for _, p := range rows {
		out.Ports = append(out.Ports, OpenPortResponse{
			AssetID: p.AssetID.String(), Address: p.Address, Hostname: p.Hostname,
			Port: p.Port, Protocol: p.Protocol, Service: p.Service, Product: p.Product,
			Identified: p.Identified, LastSeen: p.LastSeen,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// ScanPortResponse is one open port a scan saw.
type ScanPortResponse struct {
	Address    string    `json:"address"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	SafetyMode string    `json:"safety_mode,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// ScanResultsResponse is what one scan found (ADR-103 decision 3).
type ScanResultsResponse struct {
	ScanID string             `json:"scan_id"`
	Ports  []ScanPortResponse `json:"ports"`
	Hosts  int                `json:"hosts" doc:"Distinct addresses with at least one open port in this scan's results."`

	Truncated bool `json:"truncated"`
	Limit     int  `json:"limit"`

	// Ephemeral says these rows come from observations, which are pruned
	// (ADR-016), so this view empties with age while the asset's services
	// persist. Always true today; a field rather than a fixed sentence in the
	// console so the screen states a server-owned fact rather than a belief
	// about retention.
	Ephemeral bool `json:"ephemeral" doc:"These results are read from observations, which age out (ADR-016). An older scan shows fewer, and eventually none, while what it taught the asset remains on the asset."`
}

const scanResultsCap = 2000

func (s *Server) scanResults(w http.ResponseWriter, r *http.Request) {
	scanID, err := pathUUID(r, "scan_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "scan_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	var (
		scan  *store.Scan
		ports []store.ScanPort
	)
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		scan, err = (store.Scans{}).Get(ctx, c, scanID)
		if err != nil {
			return err
		}
		// The window is the scan's own life, widened at both ends: a task may
		// be observed slightly before the row's created_at is committed, and a
		// scan that is still running has no end.
		since := scan.CreatedAt.Add(-time.Hour)
		ports, err = (store.Observations{}).OpenPortsForScan(ctx, c, scanID, since, time.Now().UTC().Add(time.Hour), scanResultsCap+1)
		return err
	}); err != nil {
		s.storeError(w, r, err)
		return
	}

	out := ScanResultsResponse{
		ScanID: scanID.String(), Ports: []ScanPortResponse{},
		Limit: scanResultsCap, Ephemeral: true,
	}
	if len(ports) > scanResultsCap {
		out.Truncated = true
		ports = ports[:scanResultsCap]
	}
	hosts := map[string]struct{}{}
	for _, p := range ports {
		hosts[p.Address] = struct{}{}
		out.Ports = append(out.Ports, ScanPortResponse{
			Address: p.Address, Port: p.Port, Protocol: p.Protocol,
			SafetyMode: p.SafetyMode, ObservedAt: p.ObservedAt,
		})
	}
	out.Hosts = len(hosts)
	writeJSON(w, r, s.log, http.StatusOK, out)
}
