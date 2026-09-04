// Package rules is the Core-side rule engine: it reads what the scan gathered
// and decides what it means (ADR-013).
//
// ============================================================================
// Evaluators are CODE and closed. Rules are CONTENT and open.
// ============================================================================
//
// `rules.detection_logic` is jsonb, so the schema committed to rules-as-data
// before this package existed. What the data means is decided here: a rule row
// names an EVALUATOR from a closed vocabulary and carries that evaluator's
// PARAMETERS. The vocabulary is Go, amendment-gated the way probe kinds are
// (ADR-049); the rows are pack-shippable and signable under ADR-019 — a pack can
// tune a threshold, re-weight a severity, or add a row against an existing
// evaluator, and a new evaluator is a Core deploy, which ADR-013 says a rule
// correction is anyway.
//
// What this DEFERS is a predicate language, and the trigger for writing one is
// concrete rather than aspirational: the first rule that needs logic no evaluator
// provides AND where adding an evaluator would be the THIRD of essentially the
// same shape. Two similar evaluators is coincidence; three is a predicate language
// asking to be written. ADR-025 says build the rule engine and the rule language
// ourselves, and this is the engine that will host the language when the third
// arrives.
//
// # Every rule here is evidence-based
//
// ADR-013 splits detection on whether the test and the verdict are separable.
// Everything in this package reads a certificate, a host key, a banner or a
// header that session 13 already gathered and stored. Nothing here sends a
// packet, and nothing here needs one: a rule correction is a re-evaluation over
// stored observations, not a rescan.
package rules

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Rule is one row of `rules`, as this engine reads it.
type Rule struct {
	ID       uuid.UUID
	Name     string
	Category string

	// Evaluator names the code that decides. A name this build does not
	// implement is REFUSED at load, not ignored: a rule that silently never
	// fires is the failure a rule engine is for.
	Evaluator string

	// Params are the evaluator's inputs — a threshold, a port list, a header
	// list. Content, so a pack can tune them without a deploy.
	Params json.RawMessage

	Severity    string
	Confidence  float64
	CWE         string
	Remediation string
	Version     int
}

// Subject is what a rule looks at: one asset, and every service observation of
// it in the window.
//
// Built from OBSERVATIONS rather than from the derived `services` rows, and
// deliberately so. The observation carries the zone it was seen from — which is
// what exposure is (ADR-008) — and the raw evidence excerpt the rule quotes; the
// services row carries neither. Building from observations also makes
// re-evaluation over history the same code path as first evaluation, which is
// the property ADR-013's retroactive correction rests on.
type Subject struct {
	AssetID     uuid.UUID
	Environment string

	Services []ServiceObservation

	// ZoneType resolves a zone id to its type. Injected rather than looked up,
	// because the evaluator must not do I/O — that is what makes it re-runnable
	// over history.
	ZoneType func(uuid.UUID) string
}

// ServiceObservation is one `service` observation, decoded.
type ServiceObservation struct {
	ObservationID uuid.UUID
	ZoneID        uuid.UUID
	ObservedAt    time.Time

	Address  string
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
	Method   string
	Evidence string

	TLS *TLSEvidence
	SSH *SSHEvidence
}

// TLSEvidence mirrors the engine's `tls` object (ADR-048 §5). A subset: only
// what rules read. The raw object is on the observation and on the service row.
type TLSEvidence struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ChainLength int    `json:"chain_length"`
	Chain       []struct {
		Fingerprint        string `json:"fingerprint"`
		Subject            string `json:"subject"`
		Issuer             string `json:"issuer"`
		NotAfter           string `json:"not_after"`
		NotBefore          string `json:"not_before"`
		SelfSigned         bool   `json:"self_signed"`
		IsCA               bool   `json:"is_ca"`
		PublicKeyAlgorithm string `json:"public_key_algorithm"`
		KeyBits            int    `json:"key_bits"`
	} `json:"chain"`
}

// SSHEvidence mirrors the engine's `ssh` object (ADR-049).
type SSHEvidence struct {
	HostKeyType       string   `json:"host_key_type"`
	Fingerprint       string   `json:"fingerprint"`
	HostKeyAlgorithms []string `json:"host_key_algorithms"`
	KexAlgorithms     []string `json:"kex_algorithms"`
}

// Finding is what an evaluator raises. The engine turns it into a row.
type Finding struct {
	Rule    Rule
	Service ServiceObservation

	// Summary is the one-line human statement of what was found. Specific to the
	// instance — "expires in 6 days", not "certificate expiring" — because a
	// finding an operator cannot verify by hand from its own text is one they
	// will dispute.
	Summary string

	// Evidence is what the rule read, copied. It goes into `evidence.data` with
	// the observation id beside it as a soft reference, and it is the copy that
	// survives the observation partition dropping (ADR-016).
	Evidence map[string]any

	// Confidence may lower the rule's base. A rule reading a self-description is
	// surer than one inferring from a response shape, and that difference has to
	// survive into the finding because ADR-014 makes confidence decide how a
	// finding is presented.
	Confidence float64
}

// Evaluator is one entry in the closed vocabulary.
//
// Pure: no I/O, no clock read — `now` is a parameter, because a rule replayed
// next year over this year's observations must reach the answer it reached at
// the time.
type Evaluator func(r Rule, s Subject, now time.Time) ([]Finding, error)

// NetworkDedupKey is ADR-010's network key: asset, port, protocol, rule.
//
// The ASSET, not the address — a host that moves keeps its findings, which is
// the whole point of session 14's identity work. The same issue seen from two
// vantage points is ONE finding with two exposures, so the zone is deliberately
// absent. Frozen once findings exist: changing it later migrates or orphans
// every finding that carries it.
func NetworkDedupKey(asset uuid.UUID, port int, protocol, rule string) string {
	return fmt.Sprintf("network|%s|%d|%s|%s", asset, port, protocol, rule)
}

// Locator is the instance locator for a network finding: the endpoint. Used by
// the lifecycle to tell "this endpoint was re-observed and the rule did not
// fire" from "this endpoint was not scanned", which are different facts.
func Locator(port int, protocol string) string {
	return fmt.Sprintf("%d/%s", port, protocol)
}
