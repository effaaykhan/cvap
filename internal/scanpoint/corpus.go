package scanpoint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// The fingerprint corpus: signed content, and a policy it cannot widen.
//
// ============================================================================
// The pack decides WHAT TO MATCH. The runtime decides WHAT MAY BE SENT.
// ============================================================================
//
// ADR-019 names the fingerprint corpus among the knowledge data that is
// versioned, signed and offline-importable, so the corpus arriving as a pack is
// a recorded decision rather than a new one. Session 12 put a probe corpus in
// this binary instead, which was right for two probes and does not survive
// content that needs continuous maintenance (execution-plan §3.5).
//
// What a signed pack does NOT settle is safety. A signature proves origin, not
// that a payload is inert — nothing about signing a pack stops it carrying a
// probe to port 9100, where a bare line is a print job. If a pack could add any
// probe, whoever signs it decides what packets leave a customer's network, which
// is a larger authority than "content update".
//
// So the split: the pack supplies patterns and payloads, and this file applies a
// CLOSED policy the pack cannot override. Violations are DROPPED AND REPORTED,
// never silently trimmed — the same rule Jobs.Tasks takes against truncation,
// for the same reason: a quietly reduced corpus is under-identification that
// looks like a clean run.

// Corpus is the fingerprint content this scan point will actually use.
//
// Built-in plus whatever a verified pack adds. The built-in half is code, ships
// in the binary and is reviewed like code; the pack half is content, arrives
// signed, and is filtered by the static policy below before it gets here.
//
// A scan point with no pack still identifies services. That is not fail-OPEN —
// nothing is widened by the absence of a pack, and the built-in set is the same
// reviewed corpus that shipped before packs existed. What it is not is COMPLETE,
// and RulePackStatus says so upstream rather than leaving Core to infer full
// coverage from silence.
type Corpus struct {
	// PackID and Version are empty when nothing but the built-in set is loaded.
	PackID  string
	Version string

	BannerMatches []enginewire.Match
	Probes        []enginewire.Probe
}

// BuiltinCorpus is what this binary knows without any pack at all.
//
// Run through the SAME static policy a pack is, and this is not ceremony. The
// policy was written for content that arrives signed, which left the in-binary
// half exempt by construction — exactly the gap where a probe to 9100 would sit
// unnoticed, and exactly the asymmetry an auditor is entitled to point at. It
// also makes `test/safety/corpusdump` honest: the gate says it prints the corpus
// after the static safety policy, and now it does.
//
// A rejection here is a BUG in this binary rather than in somebody's pack, so it
// is returned for the caller to report the same way — loudly — instead of being
// swallowed by an in-package assumption that the built-ins must be fine.
func BuiltinCorpus() (*Corpus, []string) {
	pack := FingerprintPack{
		FormatVersion: PackFormatVersion,
		Probes:        ProbeCorpus(),
		BannerMatches: BuiltinBannerMatches(),
	}
	rejected := applyProbePolicy(&pack)
	return &Corpus{BannerMatches: pack.BannerMatches, Probes: pack.Probes}, rejected
}

// Merge adds a verified pack's content to the built-in set.
//
// Additive, and the built-in half WINS a collision. A pack that could redefine
// `http-head` could change what those bytes are while the observation still
// named the probe an operator has read the source of — so a name collision is a
// rejection, reported like any other, rather than a quiet substitution.
//
// Banner matches are appended AFTER the built-in ones because first hit wins:
// a pack extends the tail of the list and cannot shadow a reviewed rule.
func (c *Corpus) Merge(pack *FingerprintPack) []string {
	var rejected []string
	c.PackID, c.Version = pack.PackID, pack.Version

	have := make(map[string]bool, len(c.Probes))
	for _, p := range c.Probes {
		have[p.Name] = true
	}
	for _, p := range pack.Probes {
		if have[p.Name] {
			rejected = append(rejected, fmt.Sprintf(
				"probe %q: a built-in probe already has that name, and the name is "+
					"what an observation is traced by", p.Name))
			continue
		}
		have[p.Name] = true
		c.Probes = append(c.Probes, p)
	}
	c.BannerMatches = append(c.BannerMatches, pack.BannerMatches...)
	return rejected
}

// ErrPackUnsigned means the pack did not verify against the configured key.
var ErrPackUnsigned = errors.New("scanpoint: fingerprint pack signature is not valid")

// ErrPackMalformed means the pack verified and could not be understood.
//
// Distinguished from ErrPackUnsigned because the operator response differs: a
// bad signature is a distribution or trust problem, and a bad format is a
// producer bug in something that was legitimately signed.
var ErrPackMalformed = errors.New("scanpoint: fingerprint pack is malformed")

// signedPack is the on-disk wrapper.
//
// The payload travels base64-encoded rather than as embedded JSON so that what
// is signed is exactly a byte string, with no room for a canonicalisation
// argument. Two JSON documents that differ only in key order are the same
// document and different bytes; a signature over "the JSON" would have to say
// which, and every scheme that has tried has regretted it.
type signedPack struct {
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}

// FingerprintPack is the content itself.
type FingerprintPack struct {
	PackID        string             `json:"pack_id"`
	Version       string             `json:"version"`
	FormatVersion int                `json:"format_version"`
	BannerMatches []enginewire.Match `json:"banner_matches"`
	Probes        []enginewire.Probe `json:"probes"`
}

// PackFormatVersion is what this build understands.
//
// A pack from the future is REFUSED rather than read best-effort: a format
// change that added a field this build ignores would mean silently applying a
// rule that means something else now, and the whole point of a signed corpus is
// that what runs is what was authored.
const PackFormatVersion = 1

// LoadFingerprintPack reads, verifies and filters a pack.
//
// Returns the surviving corpus and the list of rejections, which the caller
// reports upstream. A pack with every probe rejected still loads: its banner
// matches are content too, and safe mode uses nothing else.
func LoadFingerprintPack(path string, pubKey ed25519.PublicKey) (*FingerprintPack, []string, error) {
	// #nosec G304 -- operator-supplied configuration path, read once at startup,
	// same class as CVAP_SP_CA_BUNDLE.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("scanpoint: reading fingerprint pack: %w", err)
	}

	var wrapper signedPack
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, nil, fmt.Errorf("%w: not a signed-pack envelope: %w", ErrPackMalformed, err)
	}
	sig, err := base64.StdEncoding.DecodeString(wrapper.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature is not base64", ErrPackUnsigned)
	}
	payload, err := base64.StdEncoding.DecodeString(wrapper.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload is not base64: %w", ErrPackMalformed, err)
	}

	// Verified BEFORE the payload is parsed. Parsing attacker-controlled JSON is
	// a smaller surface than parsing it and then acting on it, but it is not
	// nothing, and there is no reason to do it for bytes nobody vouched for.
	if len(pubKey) != ed25519.PublicKeySize || !ed25519.Verify(pubKey, payload, sig) {
		return nil, nil, ErrPackUnsigned
	}

	var pack FingerprintPack
	if err := json.Unmarshal(payload, &pack); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrPackMalformed, err)
	}
	if pack.FormatVersion != PackFormatVersion {
		return nil, nil, fmt.Errorf("%w: format version %d, this build reads %d",
			ErrPackMalformed, pack.FormatVersion, PackFormatVersion)
	}

	rejected := applyProbePolicy(&pack)
	return &pack, rejected, nil
}

// ============================================================================
// The static probe policy. CLOSED — adding to it is an amendment, not config.
// ============================================================================
//
// Enumerated here and in ADR-048, and deliberately not reachable from any
// environment variable or pack field. A policy a deployment can widen is not a
// policy: the argument for letting a signed pack supply probes rests entirely on
// the runtime holding a limit the pack cannot move, and a `CVAP_SP_ALLOW_...`
// escape hatch would hand that back to whoever writes the deployment manifest.
//
// The four rules:
//
//  1. No probe to a port where unsolicited bytes are not inert.
//  2. No probe payload larger than MaxProbePayload.
//  3. No probes at all in safe mode — enforced in job.budget by handing over an
//     empty list, not here.
//  4. No probes at all for a fragile target — likewise.
//
// Rules 3 and 4 are listed for completeness and live in job.budget, because they
// are decisions about a JOB and these are decisions about a PACK.

// nonInertPorts is rule 1: ports where a payload does something rather than
// nothing.
//
// Not a guess. 9100 is raw print, where any bytes are a print job; 515 and 631
// are the other printing protocols; 502, 102, 20000, 44818 and 47808 are
// industrial control, where an unsolicited frame reaches a PLC's protocol stack.
// Invariant 9 is that detection establishes evidence without achieving impact,
// and printing a page is impact.
var nonInertPorts = map[uint32]string{
	515:   "LPD printing",
	631:   "IPP printing",
	9100:  "raw print (JetDirect): any bytes are a print job",
	102:   "S7 / ISO-TSAP (industrial)",
	502:   "Modbus (industrial)",
	20000: "DNP3 (industrial)",
	44818: "EtherNet/IP (industrial)",
	47808: "BACnet (building control)",
}

// MaxProbePayload is rule 2.
//
// A probe is a protocol greeting; 512 bytes is generous for one. The bound is
// here rather than trusted to the pack because a large payload is how a probe
// becomes something other than a probe.
//
// Measured against the SUBSTITUTED size, not the authored one. A safety audit
// drove a 510-byte probe made of 51 `{{target}}` placeholders through the policy
// and captured 867 bytes on the wire against a v4-mapped address — and ~1989
// against a full IPv6 target, four times the bound. Substitution happens in the
// engine, after every check in this package, so a bound on the authored bytes
// bounds the wrong thing.
const MaxProbePayload = 512

// substitutedSize is the worst case after the engine replaces placeholders.
//
// Worst case rather than actual, because the policy runs once at load and the
// targets are not known until a job arrives. A probe that fits for one address
// and not another is a probe whose safety depends on which host is being
// scanned, which is not a property anybody could reason about.
func substitutedSize(payload []byte) int {
	n := bytes.Count(payload, []byte(ProbeTargetPlaceholder))
	return len(payload) + n*(MaxTargetLength-len(ProbeTargetPlaceholder))
}

// MaxPackProbes bounds the corpus itself.
//
// Not one of the four safety rules — it is a denial-of-service bound on this
// runtime rather than on a target. A pack with a hundred thousand probes would
// be handed to an engine over a pipe.
const MaxPackProbes = 2000

// applyProbePolicy drops what the pack may not send and returns why.
func applyProbePolicy(pack *FingerprintPack) []string {
	var rejected []string
	kept := pack.Probes[:0]

	for _, p := range pack.Probes {
		if len(kept) >= MaxPackProbes {
			rejected = append(rejected, fmt.Sprintf(
				"probe %q and those after it: pack exceeds %d probes", p.Name, MaxPackProbes))
			break
		}
		if p.Name == "" {
			rejected = append(rejected, "a probe with no name: it could not be traced from the observation it produced")
			continue
		}
		if !knownProbeKind(p.Kind) {
			// A kind this build cannot bound is a probe whose behaviour is
			// unknown, and the safe reading of unknown is no. Same direction the
			// pack format version takes, and for the same reason: what runs must
			// be what was authored, not a best-effort reading of it.
			rejected = append(rejected, fmt.Sprintf(
				"probe %q has kind %q, which this build does not implement", p.Name, p.Kind))
			continue
		}
		if grown := substitutedSize(p.Payload); p.Kind == enginewire.ProbeKindPayload &&
			grown > MaxProbePayload {
			rejected = append(rejected, fmt.Sprintf(
				"probe %q: payload is %d bytes and %d after target substitution, limit is %d",
				p.Name, len(p.Payload), grown, MaxProbePayload))
			continue
		}
		if bad, why := firstNonInertPort(p.Ports); why != "" {
			rejected = append(rejected, fmt.Sprintf(
				"probe %q targets port %d: %s", p.Name, bad, why))
			continue
		}
		if len(p.Ports) == 0 {
			// A probe with no ports is sent to EVERY open port, which cannot be
			// checked against the denylist at all. Refused rather than
			// port-filtered, because "every port" includes the ones above.
			rejected = append(rejected, fmt.Sprintf(
				"probe %q names no ports, so it would be sent to every open one including "+
					"those where bytes are not inert", p.Name))
			continue
		}
		if p.Kind == enginewire.ProbeKindPayload && !p.TLS && len(p.Payload) == 0 {
			// A probe that sends nothing is a connect, and the engine already
			// connects to every port it examines — so this is a second full
			// connection bought for nothing, per port, per host.
			//
			// The first version of this rule refused a TLS probe with no payload
			// too, and running the BUILT-IN corpus through the policy is what
			// showed that to be wrong: `tls-hello` deliberately handshakes and
			// sends no application data, because the CERTIFICATE is what it is
			// buying and the engine records that whether or not a rule fires.
			// The rule was written about payloads when it is really about
			// whether anything at all leaves the socket.
			rejected = append(rejected, fmt.Sprintf(
				"probe %q sends nothing and does not handshake, so it is a connect the "+
					"engine already makes", p.Name))
			continue
		}
		if bad, ok := firstImpossiblePort(p.Ports); !ok {
			// A port outside 1..65535 is not a port. The engine drops it rather
			// than truncating — `toPorts` in the process shell — so this is
			// inert today, and it is refused here anyway: the safety of a
			// denylist that compares numbers must not rest on a narrowing
			// conversion two processes away behaving one way rather than the
			// other. 65636 truncates to 100; 74636 truncates to 9100.
			rejected = append(rejected, fmt.Sprintf(
				"probe %q names port %d, which is not a port", p.Name, bad))
			continue
		}
		// A probe carrying no matches is NOT refused, and that was a rule this
		// file briefly had.
		//
		// A safety audit called a matchless probe pure packet spend, which is
		// true of a probe read in isolation and false of this engine: runProbe
		// evaluates a probe's response against the job's BANNER rules when the
		// probe's own rules do not fire. The built-in `newline` probe depends on
		// exactly that — it provokes a greeting and the greeting rules read it —
		// and running the built-ins through this policy is what caught the rule
		// being wrong, for the second time.
		if why := badPatterns(p.Matches); why != "" {
			rejected = append(rejected, fmt.Sprintf("probe %q: %s", p.Name, why))
			continue
		}
		kept = append(kept, p)
	}
	pack.Probes = kept

	keptBanner := pack.BannerMatches[:0]
	for i, m := range pack.BannerMatches {
		if why := badPatterns([]enginewire.Match{m}); why != "" {
			rejected = append(rejected, fmt.Sprintf("banner match %d: %s", i, why))
			continue
		}
		keptBanner = append(keptBanner, m)
	}
	pack.BannerMatches = keptBanner

	return rejected
}

// firstImpossiblePort reports a port number outside the valid range.
func firstImpossiblePort(ports []uint32) (uint32, bool) {
	for _, p := range ports {
		if p == 0 || p > 65535 {
			return p, false
		}
	}
	return 0, true
}

func firstNonInertPort(ports []uint32) (uint32, string) {
	for _, p := range ports {
		if why, bad := nonInertPorts[p]; bad {
			return p, why
		}
	}
	return 0, ""
}

// knownProbeKind reports whether this build implements a probe kind.
//
// A CLOSED set, checked the same way the pack format version is: a kind this
// build cannot bound is a probe whose behaviour is unknown, and the safe reading
// of unknown is no. Adding one is an amendment (ADR-049), not a config value —
// the same rule the port denylist is under, because a kind is exactly a
// statement about what may leave the socket.
func knownProbeKind(k string) bool {
	switch k {
	case enginewire.ProbeKindPayload, enginewire.ProbeKindSSHHostKey:
		return true
	default:
		return false
	}
}

// badPatterns rejects a rule whose regexp will not compile or has no service.
//
// Compiled HERE, in the runtime, rather than only in the engine. A pattern that
// fails to compile in the engine is a rule that silently matches nothing — which
// is under-identification, and the corpus is exactly where that must be loud.
func badPatterns(ms []enginewire.Match) string {
	for _, m := range ms {
		if m.Service == "" {
			return "a match with no service name identifies nothing"
		}
		if m.Soft && m.Product != "" {
			// Soft means "protocol known, product not". A rule claiming both is
			// two different answers, and the engine resolves softness from the
			// product it ends up with — so this would be a declaration the
			// engine silently disagrees with.
			return fmt.Sprintf("match for %q is marked soft and names product %q", m.Service, m.Product)
		}
		if m.Confidence <= 0 || m.Confidence > 1 {
			// Zero is the dangerous one: it is what an omitted field decodes to,
			// and a rule that fires at zero confidence is a rule whose result
			// ADR-014 will present as worthless. Refused rather than defaulted,
			// because guessing a confidence on the pack's behalf invents
			// evidence quality nobody authored.
			return fmt.Sprintf("match for %q has confidence %v, which is not in (0,1]", m.Service, m.Confidence)
		}
		if _, err := regexp.Compile(m.Pattern); err != nil {
			return fmt.Sprintf("pattern %q does not compile: %v", m.Pattern, err)
		}
	}
	return ""
}

// LoadCorpus resolves the fingerprint content this runtime will use, and what
// to tell Core about it.
//
// ============================================================================
// A pack that will not verify is REFUSED and REPORTED. It is not fatal.
// ============================================================================
//
// Refusing to start would turn a content problem into an outage: a scan point
// offline identifies nothing at all, which is strictly worse than one running on
// the built-in set. ADR-019's requirement is not that a bad pack stops the
// process — it is that the refusal is not silent, because "the pack is not
// loaded, detection silently regresses, and nothing says so" is the failure it
// was written against. So the status goes upstream on every connect.
//
// Returns the corpus and the status to report. Never nil, never an error: every
// path here has an answer, and the answer is always at least the built-in set.
func LoadCorpus(cfg Config, log *slog.Logger) (*Corpus, *scanpointv1.RulePackStatus) {
	corpus, builtinRejected := BuiltinCorpus()
	for _, why := range builtinRejected {
		// A built-in that fails the policy is a bug in THIS binary, not in
		// somebody's pack. Logged at error for that reason.
		log.Error("a BUILT-IN probe was refused by the static safety policy",
			slog.String("reason", why))
	}

	if cfg.FingerprintPackPath == "" {
		// Nothing configured. Reported all the same, because Core cannot
		// otherwise distinguish a scan point running on built-ins from one
		// running a pack it has forgotten about — and offline import (ADR-019)
		// means Core never knows what is live unless it is told.
		return corpus, &scanpointv1.RulePackStatus{
			State:  scanpointv1.RulePackState_RULE_PACK_STATE_UNSPECIFIED,
			Detail: "no fingerprint pack configured; running the built-in match set only",
		}
	}

	key, err := loadPackKey(cfg.FingerprintKeyPath)
	if err != nil {
		log.Error("fingerprint pack key unusable; running the built-in match set only",
			slog.String("path", cfg.FingerprintKeyPath), slog.Any("error", err))
		return corpus, &scanpointv1.RulePackStatus{
			State:  scanpointv1.RulePackState_REJECTED_SIGNATURE,
			Detail: "verification key unusable: " + err.Error(),
		}
	}

	pack, rejected, err := LoadFingerprintPack(cfg.FingerprintPackPath, key)
	if err != nil {
		state := scanpointv1.RulePackState_REJECTED_FORMAT
		if errors.Is(err, ErrPackUnsigned) {
			state = scanpointv1.RulePackState_REJECTED_SIGNATURE
		}
		log.Error("fingerprint pack refused; running the built-in match set only",
			slog.String("path", cfg.FingerprintPackPath), slog.Any("error", err))
		return corpus, &scanpointv1.RulePackStatus{State: state, Detail: err.Error()}
	}

	rejected = append(rejected, corpus.Merge(pack)...)

	// ========================================================================
	// Dropped AND reported. Never silently trimmed.
	// ========================================================================
	//
	// The same rule Jobs.Tasks takes against truncation, for the same reason: a
	// quietly reduced corpus is under-identification that looks like a clean
	// run. Every rejection is named individually — an operator who signed a pack
	// containing a probe to port 9100 needs to know WHICH probe, not that some
	// number of them did not load.
	for _, why := range rejected {
		log.Warn("fingerprint pack entry refused by the static safety policy",
			slog.String("pack_id", pack.PackID),
			slog.String("version", pack.Version),
			slog.String("reason", why))
	}

	detail := fmt.Sprintf("loaded: %d banner matches, %d probes", len(corpus.BannerMatches), len(corpus.Probes))
	if len(rejected) > 0 {
		detail = fmt.Sprintf("%s; %d entr%s refused by the static safety policy: %s",
			detail, len(rejected), plural(len(rejected)), strings.Join(rejected, "; "))
	}
	log.Info("fingerprint pack loaded",
		slog.String("pack_id", pack.PackID),
		slog.String("version", pack.Version),
		slog.Int("banner_matches", len(corpus.BannerMatches)),
		slog.Int("probes", len(corpus.Probes)),
		slog.Int("refused", len(rejected)))

	return corpus, &scanpointv1.RulePackStatus{
		PackId:  pack.PackID,
		Version: pack.Version,
		State:   scanpointv1.RulePackState_LOADED,
		Detail:  detail,
	}
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// loadPackKey reads the ed25519 verification key.
//
// Base64 of the 32 raw public-key bytes, one line. Not PEM: a PEM public key
// arrives through crypto/x509 parsing, and this key is read at startup on every
// scan point in the fleet — a 32-byte fixed-size decode has no parser to get
// wrong. The pack's contents are attacker-relevant; the key's encoding should
// not be.
func loadPackKey(path string) (ed25519.PublicKey, error) {
	// #nosec G304 -- operator-supplied configuration path, read once at startup.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key is not base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is %d bytes, an ed25519 public key is %d",
			len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}
