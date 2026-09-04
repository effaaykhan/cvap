package fingerprint

import "encoding/json"

// The `service` observation, and the one field that is a control rather than a
// value.

// servicePayload is what this engine produces per open port.
//
// One observation type, not several. TLS lives INSIDE it as an object rather
// than becoming its own observation type, because a certificate is a property of
// a service on a port: week 6's non-CVE rules ask "does this HTTPS service
// present an expired certificate", and splitting it would make that one question
// a join across two observations keyed on an address and a port number. ADR-048
// records this so nobody normalises it later and breaks those rules.
type servicePayload struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// Service is the protocol — ssh, http, smtp. Empty means nothing matched.
	Service string `json:"service,omitempty"`

	// Product and Version are the software, when it can be told. Product empty
	// with Service set is a SOFTMATCH, and is a correct answer: see Softmatch.
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Info    string `json:"info,omitempty"`

	// ====================================================================
	// Softmatch: "this is HTTP, product unknown" is an ANSWER, not a
	// failure.
	// ====================================================================
	//
	// A great deal of real software is configured not to name itself. Without a
	// representation for "protocol known, product not", such a service has two
	// bad outcomes: reported as unidentified, losing the port's identity, or
	// guessed at, which is worse because ADR-014 will match a guess against a
	// vendor advisory feed.
	//
	// Derived from the resolved product rather than copied from the rule that
	// fired, so a rule declaring itself soft while naming a product cannot
	// produce a payload that contradicts itself.
	Softmatch bool `json:"softmatch,omitempty"`

	// ====================================================================
	// How this was learned, and whether we PROVOKED it.
	// ====================================================================
	//
	// Method is banner, probe, tls-probe, tls, none or refused. Solicited says
	// whether bytes left this scan point first. SafetyMode is the mode the job
	// ran under.
	//
	// All three, not one, because they answer different questions. An operator
	// asks "did we touch this host" — that is Solicited. The finding pipeline
	// asks "how much do I believe this" — that is Method and Confidence, which
	// differ sharply between a service that announced its version and one
	// inferred from the shape of an error page. An auditor asks "was this scan
	// within its authorisation" — that is SafetyMode.
	Method     string `json:"method,omitempty"`
	Solicited  bool   `json:"solicited"`
	SafetyMode string `json:"safety_mode,omitempty"`

	// Probe names which payload produced this, so a claim can be traced to what
	// was sent. Pattern names the rule that fired, for the same reason one layer
	// up: a wrong identification is debugged by reading the rule.
	Probe   string `json:"probe,omitempty"`
	Pattern string `json:"pattern,omitempty"`

	// Evidence is the sanitised response excerpt the match was made against.
	Evidence string `json:"evidence,omitempty"`

	// Detail carries a refusal reason.
	Detail string `json:"detail,omitempty"`

	OS  *osHint     `json:"os,omitempty"`
	TLS *tlsPayload `json:"tls,omitempty"`
}

// osHint is a platform a banner SUGGESTED. It is not OS detection.
//
// ============================================================================
// `authoritative` is always false, and it is false MECHANICALLY.
// ============================================================================
//
// The struct has no authoritative field to set. MarshalJSON writes the literal
// `false`, so there is no assignment anywhere in this codebase — present or
// future — that can make an OS hint claim to be authoritative. Phase 3's real OS
// detection has to change this method to get past it, which is a diff a reviewer
// sees and an ADR can be asked for. A comment saying "do not treat this as OS
// detection" is a hope; a value that cannot be set is a control.
//
// Why it matters this much: ADR-014 makes OS attribution decide which vendor
// advisory feed a host is matched against. An OpenSSH banner ending
// `Ubuntu-3ubuntu0.4` is genuinely good evidence and it is still a string the
// host chose to send, and a host that lies about its distribution gets matched
// against the wrong feed — which produces confident findings that are wrong in
// both directions, and poisons the knowledge plane rather than merely this scan.
type osHint struct {
	Hint   string
	Source string
}

func (o osHint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Hint   string `json:"hint"`
		Source string `json:"source"`

		// The literal. Not a field, not a parameter, not a default.
		Authoritative bool `json:"authoritative"`
	}{Hint: o.Hint, Source: o.Source, Authoritative: false})
}
