package rules

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The closed evaluator vocabulary.
//
// ============================================================================
// Twelve evaluators, thirteen rules, and the difference is the design working.
// ============================================================================
//
// `plaintext.service` is one evaluator with a `services` parameter, and the
// telnet rule and the FTP rule are two ROWS against it. That is what "evaluators
// are code, rules are content" buys: the second plaintext protocol cost a row,
// not a deploy.
//
// The revisit trigger for a predicate language is the first rule that needs
// logic no evaluator provides AND where adding one would be the THIRD of
// essentially the same shape. Watch `tls.expired`, `tls.expiring` and
// `tls.weak_key` — they are all "a certificate field against a threshold", and
// they are two shapes rather than three only because expiry and key size read
// different fields. A fourth certificate-threshold rule is where the language
// gets written.

// Evaluators is the vocabulary. A rule naming anything else is refused at load.
var Evaluators = map[string]Evaluator{
	"tls.expired":                   tlsExpired,
	"tls.expiring":                  tlsExpiring,
	"tls.self_signed":               tlsSelfSigned,
	"tls.missing_chain":             tlsMissingChain,
	"tls.weak_key":                  tlsWeakKey,
	"tls.legacy_negotiated":         tlsLegacyNegotiated,
	"tls.weak_cipher_negotiated":    tlsWeakCipherNegotiated,
	"plaintext.service":             plaintextService,
	"http.no_https_redirect":        httpNoHTTPSRedirect,
	"http.missing_headers":          httpMissingHeaders,
	"exposure.management_untrusted": exposureManagementUntrusted,
	"ssh.weak_algorithms":           sshWeakAlgorithms,
}

// ---------------------------------------------------------------------------
// Certificates. Direct observation of the condition: HIGH confidence.
// ---------------------------------------------------------------------------

// leafOf returns the presented leaf, which is index 0 of the chain — what
// crypto/tls puts first and what the engine fingerprinted.
func leafOf(s ServiceObservation) (leaf *struct {
	Fingerprint        string `json:"fingerprint"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	NotAfter           string `json:"not_after"`
	NotBefore          string `json:"not_before"`
	SelfSigned         bool   `json:"self_signed"`
	IsCA               bool   `json:"is_ca"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	KeyBits            int    `json:"key_bits"`
}, ok bool) {
	if s.TLS == nil || len(s.TLS.Chain) == 0 {
		return nil, false
	}
	return &s.TLS.Chain[0], true
}

func certEvidence(s ServiceObservation, extra map[string]any) map[string]any {
	leaf, ok := leafOf(s)
	if !ok {
		// Unreachable from the evaluators, which all guard with leafOf before
		// building a finding — but a security review noted it is one new cert
		// evaluator away from a nil dereference on an attacker-presented empty
		// chain, and a scanned host chooses whether to present one. Cheap to
		// make structural.
		return map[string]any{"port": s.Port, "protocol": s.Protocol}
	}
	ev := map[string]any{
		"port": s.Port, "protocol": s.Protocol,
		"fingerprint": leaf.Fingerprint, "subject": leaf.Subject, "issuer": leaf.Issuer,
		"not_before": leaf.NotBefore, "not_after": leaf.NotAfter,
		"tls_version": s.TLS.Version, "cipher_suite": s.TLS.CipherSuite,
	}
	for k, v := range extra {
		ev[k] = v
	}
	return ev
}

func tlsExpired(r Rule, sub Subject, now time.Time) ([]Finding, error) {
	var out []Finding
	for _, s := range sub.Services {
		leaf, ok := leafOf(s)
		if !ok {
			continue
		}
		notAfter, err := time.Parse(time.RFC3339, leaf.NotAfter)
		if err != nil {
			continue // a certificate whose dates cannot be read is not evidence of expiry
		}
		if !notAfter.Before(now) {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("certificate on %d/%s expired %s ago (not_after %s)",
				s.Port, s.Protocol, now.Sub(notAfter).Round(time.Hour), leaf.NotAfter),
			Evidence: certEvidence(s, map[string]any{"evaluated_at": now.UTC().Format(time.RFC3339)}),
		})
	}
	return out, nil
}

func tlsExpiring(r Rule, sub Subject, now time.Time) ([]Finding, error) {
	var p struct {
		WarnDays int `json:"warn_days"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	if p.WarnDays <= 0 {
		return nil, fmt.Errorf("rule %s: warn_days must be positive", r.Name)
	}

	var out []Finding
	for _, s := range sub.Services {
		leaf, ok := leafOf(s)
		if !ok {
			continue
		}
		notAfter, err := time.Parse(time.RFC3339, leaf.NotAfter)
		if err != nil {
			continue
		}
		// Not yet expired — that is tls.expired's finding, and raising both
		// would be two findings for one certificate.
		if notAfter.Before(now) {
			continue
		}
		remaining := notAfter.Sub(now)
		if remaining > time.Duration(p.WarnDays)*24*time.Hour {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("certificate on %d/%s expires in %d days (not_after %s)",
				s.Port, s.Protocol, int(remaining.Hours()/24), leaf.NotAfter),
			Evidence: certEvidence(s, map[string]any{
				"days_remaining": int(remaining.Hours() / 24), "warn_days": p.WarnDays,
			}),
		})
	}
	return out, nil
}

func tlsSelfSigned(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		ExemptEnvironments []string `json:"exempt_environments"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	// "On non-dev assets" is the rule's whole point. An asset with NO recorded
	// environment is NOT exempt: the default reading has to be the one that
	// raises, or every un-tagged asset is silently treated as development.
	for _, e := range p.ExemptEnvironments {
		if strings.EqualFold(strings.TrimSpace(sub.Environment), e) {
			return nil, nil
		}
	}

	var out []Finding
	for _, s := range sub.Services {
		leaf, ok := leafOf(s)
		if !ok || !leaf.SelfSigned {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("self-signed certificate on %d/%s (%s) on an asset in environment %q",
				s.Port, s.Protocol, leaf.Subject, orUnset(sub.Environment)),
			Evidence: certEvidence(s, map[string]any{"environment": sub.Environment}),
		})
	}
	return out, nil
}

func tlsMissingChain(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var out []Finding
	for _, s := range sub.Services {
		leaf, ok := leafOf(s)
		if !ok {
			continue
		}
		// A self-signed leaf IS its own chain; the finding for that is
		// tls.self_signed. A leaf presented alone that is NOT self-signed means
		// the intermediates were left out and every client has to have them
		// cached — which browsers do and everything else does not.
		if leaf.SelfSigned || s.TLS.ChainLength != 1 {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("%d/%s presents only the leaf certificate (issuer %s); no intermediate chain",
				s.Port, s.Protocol, leaf.Issuer),
			Evidence: certEvidence(s, map[string]any{"chain_length": s.TLS.ChainLength}),
		})
	}
	return out, nil
}

func tlsWeakKey(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		MinRSABits int `json:"min_rsa_bits"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	if p.MinRSABits <= 0 {
		return nil, fmt.Errorf("rule %s: min_rsa_bits must be positive", r.Name)
	}

	var out []Finding
	for _, s := range sub.Services {
		leaf, ok := leafOf(s)
		if !ok || leaf.PublicKeyAlgorithm != "RSA" {
			continue
		}
		// Zero means UNKNOWN, never small (ADR-048 §8). A key the engine could
		// not size is not evidence of a weak key.
		if leaf.KeyBits == 0 || leaf.KeyBits >= p.MinRSABits {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("RSA key on %d/%s is %d bits; minimum is %d",
				s.Port, s.Protocol, leaf.KeyBits, p.MinRSABits),
			Evidence: certEvidence(s, map[string]any{"key_bits": leaf.KeyBits, "min_rsa_bits": p.MinRSABits}),
		})
	}
	return out, nil
}

// tlsLegacyNegotiated fires when the NEGOTIATED version is 1.0 or 1.1.
//
// ============================================================================
// This is the honest form of "TLS 1.0/1.1 enabled", and it is narrower.
// ============================================================================
//
// The engine offers 1.0 through 1.3 and records what the server chose. A server
// that chose 1.0 against a client offering 1.3 speaks NOTHING better — that is a
// direct observation and a high-confidence finding. A server that chose 1.3 may
// or may not also accept 1.0, and this rule cannot see that. "Enabled" needs a
// version-ladder probe, one handshake per version, which is a packet cost per
// port and a session 13 gap named in ADR-050.
// legacyTLSVersions is the deny-set for tls.legacy_negotiated, defined once so
// the branch and the evidence match against the SAME set: a stored set that
// could differ from the one the code tested would be decorative (note: session
// 19, ADR-050's evidence rule).
var legacyTLSVersions = []string{"TLSv1.0", "TLSv1.1"}

func tlsLegacyNegotiated(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var out []Finding
	for _, s := range sub.Services {
		if s.TLS == nil {
			continue
		}
		if !containsFold(legacyTLSVersions, s.TLS.Version) {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("%d/%s negotiated %s against a client offering TLS 1.3; the server offers nothing newer",
				s.Port, s.Protocol, s.TLS.Version),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol,
				// The member matched, and the set it matched against.
				"negotiated_version": s.TLS.Version,
				"legacy_versions":    legacyTLSVersions,
				"cipher_suite":       s.TLS.CipherSuite,
				"client_offered":     "TLSv1.0 through TLSv1.3",
			},
		})
	}
	return out, nil
}

// tlsWeakCipherNegotiated: same argument, for the suite. The negotiated suite is
// the best the server would give a modern client, so a weak one is a direct
// observation. "Weak cipher ENABLED" is the same gap as the version.
//
// The weak set is crypto/tls's own — the suites Go refuses to enable by default,
// judged by people who maintain a TLS stack rather than by this file. ADR-025:
// consume the TLS stack's judgement, build the rule on it.
func tlsWeakCipherNegotiated(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	weak := map[string]bool{}
	var weakNames []string
	for _, cs := range tls.InsecureCipherSuites() {
		weak[cs.Name] = true
		weakNames = append(weakNames, cs.Name)
	}
	sort.Strings(weakNames) // stable evidence across runs

	var out []Finding
	for _, s := range sub.Services {
		if s.TLS == nil || !weak[s.TLS.CipherSuite] {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("%d/%s negotiated %s, which Go's TLS stack classes as insecure",
				s.Port, s.Protocol, s.TLS.CipherSuite),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol,
				"negotiated_version": s.TLS.Version,
				// The member matched, and the actual set it matched against —
				// crypto/tls's own InsecureCipherSuites, not just a name for it.
				"cipher_suite":    s.TLS.CipherSuite,
				"insecure_suites": weakNames,
				"classification":  "crypto/tls InsecureCipherSuites",
			},
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Plaintext protocols.
// ---------------------------------------------------------------------------

// plaintextService is one evaluator for every "this protocol is cleartext" rule.
// The telnet row and the FTP row differ by a parameter, which is exactly what a
// parameterised evaluator is for.
func plaintextService(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		Services []string `json:"services"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	if len(p.Services) == 0 {
		return nil, fmt.Errorf("rule %s: services is empty", r.Name)
	}

	var out []Finding
	for _, s := range sub.Services {
		if s.TLS != nil {
			continue // FTPS and telnet-over-TLS are not plaintext
		}
		for _, want := range p.Services {
			if !strings.EqualFold(s.Service, want) {
				continue
			}
			out = append(out, Finding{
				Rule: r, Service: s, Confidence: r.Confidence,
				Summary: fmt.Sprintf("%s on %d/%s: credentials and session content cross the network in cleartext",
					s.Service, s.Port, s.Protocol),
				Evidence: map[string]any{
					"port": s.Port, "protocol": s.Protocol, "service": s.Service,
					"product": s.Product, "version": s.Version,
					"identified_by": s.Method, "banner": s.Evidence,
				},
			})
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// HTTP, read from the EVIDENCE excerpt. A latent limitation, named.
// ---------------------------------------------------------------------------
//
// ============================================================================
// These two rules parse a status line and headers out of the sanitised
// response excerpt, not out of a structured field. That is a LATENT LIMITATION
// in the sense the project's memory now records: true and harmless today, and
// the thing that breaks the moment the excerpt format changes for an unrelated
// reason.
// ============================================================================
//
// The excerpt is what the fingerprint engine's `sanitise` produced: CR and LF
// replaced by spaces, control bytes by dots, bounded at the probe's ReadBytes.
// Header names and values survive that; header BOUNDARIES do not, which is why
// the parsing below looks for `<space>name:` rather than splitting on newlines.
//
// The fix is a structured `http` object on the service payload — status code,
// headers as a map — gathered by the engine in the same place it already
// gathers the `tls` object. Until then the confidence on these rules is MEDIUM
// rather than high, because they are inferring structure from prose.

func httpResponse(s ServiceObservation) (status int, headers map[string]string, ok bool) {
	if s.Evidence == "" || !strings.HasPrefix(s.Evidence, "HTTP/") {
		return 0, nil, false
	}
	fields := strings.Fields(s.Evidence)
	if len(fields) < 2 {
		return 0, nil, false
	}
	// strconv, not Sscanf: Sscanf("3o1") returns 3 with no error, which shifts a
	// crafted status line across the 3xx redirect band. Atoi rejects the whole
	// token unless it is entirely digits. The header VALUE-injection case a
	// security review noted (a `name:` token inside another header's value) is
	// inherent to reading prose and is why these rules ship at 0.75 and carry
	// read_from in their evidence; the structured http object (ADR-050) is the
	// real fix. This closes the one direction that is not inherent.
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, nil, false
	}
	status = code

	// Headers: a token ending in ":" that is not the first token, followed by
	// everything up to the next such token. Lowercased names, because HTTP
	// header names are case-insensitive and servers disagree about it.
	headers = map[string]string{}
	var name string
	var value []string
	for _, f := range fields[2:] {
		if strings.HasSuffix(f, ":") && len(f) > 1 && !strings.Contains(f[:len(f)-1], ":") {
			if name != "" {
				headers[name] = strings.Join(value, " ")
			}
			name, value = strings.ToLower(strings.TrimSuffix(f, ":")), nil
			continue
		}
		if name != "" {
			value = append(value, f)
		}
	}
	if name != "" {
		headers[name] = strings.Join(value, " ")
	}
	return status, headers, true
}

func httpNoHTTPSRedirect(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var out []Finding
	for _, s := range sub.Services {
		if s.Service != "http" || s.TLS != nil {
			continue // only PLAIN http; the https listener is where it should go
		}
		status, headers, ok := httpResponse(s)
		if !ok {
			continue
		}
		redirects := status >= 300 && status < 400 &&
			strings.HasPrefix(strings.ToLower(headers["location"]), "https://")
		if redirects {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("plain HTTP on %d/%s answers %d without redirecting to HTTPS",
				s.Port, s.Protocol, status),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol, "status": status,
				"location": headers["location"], "response_excerpt": s.Evidence,
				"read_from": "sanitised evidence excerpt, not a structured field",
			},
		})
	}
	return out, nil
}

func httpMissingHeaders(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		Required []string `json:"required"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	if len(p.Required) == 0 {
		return nil, fmt.Errorf("rule %s: required is empty", r.Name)
	}

	var out []Finding
	for _, s := range sub.Services {
		if s.Service != "http" {
			continue
		}
		status, headers, ok := httpResponse(s)
		if !ok || status >= 300 {
			// A redirect carries no content and legitimately carries no
			// content-security-policy; judging it would be a false finding on
			// every well-configured http->https listener.
			continue
		}
		var missing []string
		for _, h := range p.Required {
			if _, present := headers[strings.ToLower(h)]; !present {
				missing = append(missing, strings.ToLower(h))
			}
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("%d/%s is missing %s", s.Port, s.Protocol, strings.Join(missing, ", ")),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol, "status": status,
				"missing": missing, "present": headerNames(headers),
				"response_excerpt": s.Evidence,
				"read_from":        "sanitised evidence excerpt, not a structured field",
			},
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Exposure.
// ---------------------------------------------------------------------------

// exposureManagementUntrusted fires when a management port was observed FROM an
// untrusted vantage point.
//
// ============================================================================
// "Untrusted" is `external` and `dmz`, and leaving `branch` and `cloud` out is
// DELIBERATE, not an oversight.
// ============================================================================
//
// A branch office is on the inside of the perimeter for some estates and a
// hostile coffee-shop network for others; a cloud zone is the customer's own VPC
// or the public internet depending on how it was drawn. Guessing either way
// produces a wrong finding on every asset in that zone. What would settle it is
// a per-zone trust attribute the operator sets — `scan_zones.trust_level` exists
// and is an integer nobody has given a meaning to — and until it has one, the
// rule reads the two zone types whose meaning nobody disputes.
func exposureManagementUntrusted(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		Ports     []int    `json:"ports"`
		ZoneTypes []string `json:"zone_types"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}
	if len(p.Ports) == 0 || len(p.ZoneTypes) == 0 {
		return nil, fmt.Errorf("rule %s: ports and zone_types are required", r.Name)
	}
	if sub.ZoneType == nil {
		return nil, fmt.Errorf("rule %s: no zone resolver", r.Name)
	}

	mgmt := map[int]bool{}
	for _, port := range p.Ports {
		mgmt[port] = true
	}
	untrusted := map[string]bool{}
	for _, z := range p.ZoneTypes {
		untrusted[strings.ToLower(z)] = true
	}

	var out []Finding
	for _, s := range sub.Services {
		if !mgmt[s.Port] {
			continue
		}
		zt := strings.ToLower(sub.ZoneType(s.ZoneID))
		if !untrusted[zt] {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("management port %d/%s (%s) is reachable from an %s zone",
				s.Port, s.Protocol, orUnset(s.Service), zt),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol, "service": s.Service,
				// The members matched (this port, this zone type), and the two
				// sets they were matched against — the rule's management ports and
				// its untrusted zone types. Both come from the params the branch
				// tested, so the evidence cannot claim a set the code did not use.
				"observed_from_zone":   s.ZoneID.String(),
				"zone_type":            zt,
				"management_ports":     p.Ports,
				"untrusted_zone_types": p.ZoneTypes,
			},
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// SSH.
// ---------------------------------------------------------------------------

func sshWeakAlgorithms(r Rule, sub Subject, _ time.Time) ([]Finding, error) {
	var p struct {
		HostKey []string `json:"host_key"`
		Kex     []string `json:"kex"`
	}
	if err := decodeParams(r, &p); err != nil {
		return nil, err
	}

	var out []Finding
	for _, s := range sub.Services {
		if s.SSH == nil {
			continue
		}
		var offered []string
		for _, a := range s.SSH.HostKeyAlgorithms {
			if containsFold(p.HostKey, a) {
				offered = append(offered, "host-key:"+a)
			}
		}
		for _, a := range s.SSH.KexAlgorithms {
			if containsFold(p.Kex, a) {
				offered = append(offered, "kex:"+a)
			}
		}
		if len(offered) == 0 {
			continue
		}
		out = append(out, Finding{
			Rule: r, Service: s, Confidence: r.Confidence,
			Summary: fmt.Sprintf("SSH on %d/%s offers %s", s.Port, s.Protocol, strings.Join(offered, ", ")),
			Evidence: map[string]any{
				"port": s.Port, "protocol": s.Protocol,
				// The members matched (weak_offered), the sets they were matched
				// against (the rule's weak host-key and kex lists), and the host's
				// full offered lists the members were drawn from. weak_host_key_set
				// and weak_kex_set are the params the branch tested, so the stored
				// set is the one the code used.
				"weak_offered":         offered,
				"weak_host_key_set":    p.HostKey,
				"weak_kex_set":         p.Kex,
				"host_key_algorithms":  s.SSH.HostKeyAlgorithms,
				"kex_algorithms":       s.SSH.KexAlgorithms,
				"host_key_fingerprint": s.SSH.Fingerprint,
			},
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------

func decodeParams(r Rule, into any) error {
	if len(r.Params) == 0 {
		return nil
	}
	if err := json.Unmarshal(r.Params, into); err != nil {
		return fmt.Errorf("rule %s: params: %w", r.Name, err)
	}
	return nil
}

func containsFold(list []string, v string) bool {
	for _, l := range list {
		if strings.EqualFold(l, v) {
			return true
		}
	}
	return false
}

func headerNames(h map[string]string) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
