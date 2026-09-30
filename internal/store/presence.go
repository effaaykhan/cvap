package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
)

// Address presence (ADR-108). The DECISION is pure and lives in internal/domain;
// this file gathers the evidence it needs and applies the verdict it returns.
// That split is the same one ADR-006 requires for merges, for the same reason:
// this rule will be wrong at first, and a rule that can be replayed over stored
// evidence can be corrected without re-scanning a network.
type Presence struct{}

// PresenceSummary is what ADR-108 decision 6 requires be STATED. "512 assets" and
// "29 present, 483 suppressed behind one device" are different claims, and
// reporting only a smaller number would swap one wrong answer for another.
type PresenceSummary struct {
	Present   int
	Responder int
	Unknown   int
}

// Total is every live address, judged or not.
func (s PresenceSummary) Total() int { return s.Present + s.Responder + s.Unknown }

// AddressPresenceEvidence pairs one address's evidence with the row it came from.
//
// The row id lives HERE and not on domain.AddressEvidence because internal/domain
// holds no persistence concepts and must not start now. The first draft of this
// file kept the mapping in a package-level map instead, which was worse than
// ugly: two tenants gathering concurrently would overwrite each other's entries,
// and because the UPDATE is tenant-scoped the mis-keyed write would match no row
// and silently do nothing. A verdict quietly not applied is precisely the failure
// ADR-108 exists to end, so the pairing is a value that travels with the call.
type AddressPresenceEvidence struct {
	AddressID uuid.UUID
	Evidence  domain.AddressEvidence
}

// GatherEvidence reads everything the presence rule needs for one tenant: the
// range-wide per-port view, each live address's own answers, and the CIDRs that
// were actually scanned.
//
// The range-wide half is the point. A single address cannot tell you whether the
// thing answering on 5060 is a soft switch or a firewall wearing 473 addresses —
// only the population can, which is why this returns a Population rather than
// deciding per row as it reads.
func (Presence) GatherEvidence(ctx context.Context, c *Conn) (domain.Population, []AddressPresenceEvidence, error) {
	pop := domain.Population{Ports: map[domain.PortRef]domain.PortEvidence{}}

	// The scanned prefixes, for the impossible-address check. Only CIDR targets:
	// a single host target tells you nothing about a network's boundaries, and
	// inferring a prefix from one address would invent the very arithmetic this
	// check exists to avoid guessing at.
	rows, err := c.Query(ctx, `
		SELECT DISTINCT target_value FROM scan_targets
		 WHERE tenant_id = $1 AND target_type = 'cidr'`, c.Tenant().UUID())
	if err != nil {
		return pop, nil, mapError(err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return pop, nil, mapError(err)
		}
		// A malformed stored target is skipped rather than fatal: it cannot make
		// the verdict wrong, only less complete, and refusing the whole pass over
		// one bad row would suppress nothing at all.
		if p, e := netip.ParsePrefix(v); e == nil {
			pop.Networks = append(pop.Networks, p)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return pop, nil, mapError(err)
	}
	rows.Close()

	// The denominator: live addresses this tenant holds.
	if err := c.QueryRow(ctx, `
		SELECT count(*) FROM asset_addresses
		 WHERE tenant_id = $1 AND valid_to IS NULL AND ip_address IS NOT NULL`,
		c.Tenant().UUID()).Scan(&pop.Addresses); err != nil {
		return pop, nil, mapError(err)
	}

	// The range-wide per-port view. `identities` counts DISTINCT product/version
	// pairs and `identified` the rows carrying a product at all — the two numbers
	// that separate a real service population (diverse) from a responder
	// (uniform, because it is one device wearing every address).
	prows, err := c.Query(ctx, `
		SELECT s.port, s.protocol::text,
		       count(DISTINCT aa.ip_address) AS answered,
		       count(DISTINCT coalesce(s.product,'') || '/' || coalesce(s.version,'')) AS identities,
		       count(*) FILTER (WHERE coalesce(s.product,'') <> '') AS identified
		  FROM services s
		  JOIN asset_addresses aa
		    ON aa.tenant_id = s.tenant_id AND aa.asset_id = s.asset_id
		   AND aa.valid_to IS NULL AND aa.ip_address IS NOT NULL
		 WHERE s.tenant_id = $1
		 GROUP BY s.port, s.protocol`, c.Tenant().UUID())
	if err != nil {
		return pop, nil, mapError(err)
	}
	for prows.Next() {
		var e domain.PortEvidence
		if err := prows.Scan(&e.Port, &e.Protocol, &e.Answered, &e.Identities, &e.Identified); err != nil {
			prows.Close()
			return pop, nil, mapError(err)
		}
		pop.Ports[domain.PortRef{Port: e.Port, Protocol: e.Protocol}] = e
	}
	if err := prows.Err(); err != nil {
		prows.Close()
		return pop, nil, mapError(err)
	}
	prows.Close()

	// Each live address's own answers.
	arows, err := c.Query(ctx, `
		SELECT aa.address_id, host(aa.ip_address),
		       coalesce(array_agg(s.port ORDER BY s.port) FILTER (WHERE s.port IS NOT NULL), '{}') AS ports,
		       coalesce(array_agg(s.protocol::text ORDER BY s.port) FILTER (WHERE s.port IS NOT NULL), '{}') AS protos,
		       bool_or(coalesce(s.product,'') <> '') AS identified
		  FROM asset_addresses aa
		  LEFT JOIN services s
		    ON s.tenant_id = aa.tenant_id AND s.asset_id = aa.asset_id
		 WHERE aa.tenant_id = $1 AND aa.valid_to IS NULL AND aa.ip_address IS NOT NULL
		 GROUP BY aa.address_id, aa.ip_address`, c.Tenant().UUID())
	if err != nil {
		return pop, nil, mapError(err)
	}
	defer arows.Close()

	var out []AddressPresenceEvidence
	for arows.Next() {
		var id uuid.UUID
		var addr string
		var ports []int32
		var protos []string
		var identified *bool
		if err := arows.Scan(&id, &addr, &ports, &protos, &identified); err != nil {
			return pop, nil, mapError(err)
		}
		a, e := netip.ParseAddr(addr)
		if e != nil {
			continue
		}
		ev := domain.AddressEvidence{Addr: a, Identified: identified != nil && *identified}
		for i := range ports {
			proto := "tcp"
			if i < len(protos) {
				proto = protos[i]
			}
			ev.Ports = append(ev.Ports, domain.PortRef{Port: int(ports[i]), Protocol: proto})
		}
		out = append(out, AddressPresenceEvidence{AddressID: id, Evidence: ev})
	}
	return pop, out, mapError(arows.Err())
}

// RecordVerdicts applies the rule to the gathered evidence and writes the results.
//
// `unknown` clears the reason and timestamp rather than leaving the previous ones
// in place, which the CHECK in 0052 also enforces: "we do not know" has to be
// distinguishable from "we decided, once". Nothing is deleted (ADR-108
// decision 5) — a suppressed address keeps its row, its services and its history.
func (Presence) RecordVerdicts(ctx context.Context, c *Conn, pop domain.Population,
	evidence []AddressPresenceEvidence, policy domain.ResponderPolicy, at time.Time,
) (PresenceSummary, error) {
	var sum PresenceSummary
	for _, item := range evidence {
		v := domain.DecidePresence(item.Evidence, pop, policy)
		id := item.AddressID
		// Every verdict records its reason, including `unknown` — it is a real
		// judgement reached two different ways, and an operator asking why an
		// address is unjudged deserves the same answer as one asking why it was
		// suppressed (ADR-108 decision 6).
		r := v.Reason
		tt := at.UTC()
		reason, decided := &r, &tt
		if _, err := c.Exec(ctx, `
			UPDATE asset_addresses
			   SET presence = $1, presence_reason = $2, presence_decided_at = $3
			 WHERE tenant_id = $4 AND address_id = $5`,
			string(v.Presence), reason, decided, c.Tenant().UUID(), id); err != nil {
			return sum, mapError(err)
		}
		switch v.Presence {
		case domain.PresencePresent:
			sum.Present++
		case domain.PresenceResponder:
			sum.Responder++
		default:
			sum.Unknown++
		}
	}
	return sum, nil
}

// Summary counts the live addresses by verdict, for the surface ADR-108
// decision 6 requires.
func (Presence) Summary(ctx context.Context, c *Conn) (PresenceSummary, error) {
	const q = `
		SELECT count(*) FILTER (WHERE presence = 'present'),
		       count(*) FILTER (WHERE presence = 'responder'),
		       count(*) FILTER (WHERE presence = 'unknown')
		  FROM asset_addresses
		 WHERE tenant_id = $1 AND valid_to IS NULL AND ip_address IS NOT NULL`
	var s PresenceSummary
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).Scan(&s.Present, &s.Responder, &s.Unknown)
	return s, mapError(err)
}
