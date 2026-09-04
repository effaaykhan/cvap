package scanpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// The static safety policy a signed pack cannot widen.
//
// ============================================================================
// These tests are the whole argument for letting a pack supply probes at all.
// ============================================================================
//
// A signature proves ORIGIN, not that a payload is inert. Nothing about signing
// a pack stops it carrying a probe to port 9100, where a bare line is a print
// job. The case for content-distributed probes rests entirely on the runtime
// holding a limit the pack cannot move — so a test that only checked "a signed
// pack loads" would be testing the easy half.
//
// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/scanpoint/corpus.go
// mutate:test    ./internal/scanpoint/ -run TestAProbeTo|TestAnOversized|TestAProbeWithNoPorts|TestAnUnsigned|TestTheSignature|TestAPackFromTheFuture|TestABuiltinProbeName|TestARuleThatIsSoft|TestZeroConfidence|TestABadPackLeaves|TestAProbeThatSendsNothing|TestAProbeGrows|TestAPortOutsideTheRange
//
// mutate:case    the non-inert port denylist is consulted and ignored
// mutate:old     if bad, why := firstNonInertPort(p.Ports); why != "" {
// mutate:new     if bad, why := firstNonInertPort(nil); why != "" {
//
// mutate:case    an oversized payload is not bounded at all
// mutate:old     grown > MaxProbePayload {
// mutate:new     grown > 1<<30 {
//
// mutate:case    a probe naming no ports is sent to every open one
// mutate:old     if len(p.Ports) == 0 {
// mutate:new     if len(p.Ports) == -1 {
//
// mutate:case    the signature is not checked at all
// mutate:old     if len(pubKey) != ed25519.PublicKeySize || !ed25519.Verify(pubKey, payload, sig) {
// mutate:new     if len(pubKey) != ed25519.PublicKeySize || ed25519.Verify(pubKey, payload, sig) && false {
//
// Dropping the Verify call outright was the obvious form and it leaves `sig`
// unused, so the mutant does not compile and tests nothing. Disabling the
// condition while still evaluating it reaches the same behaviour — any pack
// loads — and compiles.
//
// mutate:case    a pack in an unknown format is read best-effort
// mutate:old     if pack.FormatVersion != PackFormatVersion {
// mutate:new     if false {
//
// mutate:case    a pack probe silently replaces a built-in one of the same name
// mutate:old     if have[p.Name] {
// mutate:new     if false {
//
// mutate:case    a probe that sends nothing is accepted and costs a connect per port
// mutate:old     if !p.TLS && len(p.Payload) == 0 {
// mutate:new     if false {
//
// mutate:case    the payload bound ignores what target substitution adds
// mutate:old     if grown := substitutedSize(p.Payload); grown > MaxProbePayload {
// mutate:new     if grown := len(p.Payload); grown > MaxProbePayload {
//
// mutate:case    a port outside the range reaches the engine to be truncated there
// mutate:old     if bad, ok := firstImpossiblePort(p.Ports); !ok {
// mutate:new     if bad, ok := firstImpossiblePort(nil); !ok {

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// writePack signs a pack and puts it on disk, the way an offline import would.
func writePack(t *testing.T, priv ed25519.PrivateKey, pack FingerprintPack) string {
	t.Helper()
	payload, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return writeRaw(t, priv, payload)
}

func writeRaw(t *testing.T, priv ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	sig := ed25519.Sign(priv, payload)
	env, err := json.Marshal(signedPack{
		Signature: base64.StdEncoding.EncodeToString(sig),
		Payload:   base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validPack(probes ...enginewire.Probe) FingerprintPack {
	return FingerprintPack{
		PackID: "cvap-fingerprint", Version: "2026.09.1",
		FormatVersion: PackFormatVersion,
		Probes:        probes,
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestAProbeToANonInertPortIsDroppedAndReported.
//
// ============================================================================
// 9100 is raw print. A bare line there is a print job, not a fingerprint.
// ============================================================================
//
// Invariant 9: detection establishes evidence without achieving impact, and
// printing a page is impact. The same applies to the industrial ports, where an
// unsolicited frame reaches a PLC's protocol stack.
//
// Dropped AND reported, never silently trimmed — a quietly reduced corpus is
// under-identification that looks like a clean run.
func TestAProbeToANonInertPortIsDroppedAndReported(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(
		enginewire.Probe{Name: "print-me", Ports: []uint32{80, 9100}, Payload: []byte("\r\n")},
		enginewire.Probe{Name: "modbus", Ports: []uint32{502}, Payload: []byte("x")},
		enginewire.Probe{Name: "fine", Ports: []uint32{8080}, Payload: []byte("x")},
	))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatalf("LoadFingerprintPack: %v", err)
	}
	if len(pack.Probes) != 1 || pack.Probes[0].Name != "fine" {
		t.Fatalf("surviving probes: %+v", pack.Probes)
	}
	if len(rejected) != 2 {
		t.Fatalf("want two rejections, got %d: %v", len(rejected), rejected)
	}
	joined := strings.Join(rejected, " ")
	if !strings.Contains(joined, "print-me") || !strings.Contains(joined, "9100") {
		t.Errorf("the rejection does not name the probe and the port: %q", joined)
	}
	if !strings.Contains(joined, "modbus") {
		t.Errorf("the industrial-port probe was not reported: %q", joined)
	}
}

// TestAnOversizedPayloadIsRefusedRatherThanTruncated.
//
// A probe is a protocol greeting. A large payload is how a probe becomes
// something other than a probe, and truncating one would send a fragment of
// whatever it was — which is neither the authored probe nor nothing.
func TestAnOversizedPayloadIsRefusedRatherThanTruncated(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(enginewire.Probe{
		Name: "fat", Ports: []uint32{8080}, Payload: make([]byte, MaxProbePayload+1),
	}))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Probes) != 0 {
		t.Errorf("an oversized probe survived: %+v", pack.Probes)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "fat") {
		t.Errorf("rejections: %v", rejected)
	}
}

// TestAProbeWithNoPortsIsRefusedBecauseTheDenylistCannotBeApplied.
//
// "Every open port" includes the ones where bytes are not inert, so a probe with
// no port scope cannot be checked against the denylist at all. Refused outright
// rather than port-filtered: filtering would silently turn an authored probe
// into a different one.
func TestAProbeWithNoPortsIsRefusedBecauseTheDenylistCannotBeApplied(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(enginewire.Probe{Name: "everywhere", Payload: []byte("\r\n")}))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Probes) != 0 {
		t.Error("a probe with no ports survived and would be sent to every open port")
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "every open one") {
		t.Errorf("rejections: %v", rejected)
	}
}

// TestAnUnsignedPackIsRefusedEntirely.
//
// Not filtered, not partially loaded. A pack nobody vouched for has no claim on
// this scan point's send path.
func TestAnUnsignedPackIsRefusedEntirely(t *testing.T) {
	pub, _ := testKey(t)
	_, other := testKey(t)
	path := writePack(t, other, validPack(enginewire.Probe{
		Name: "fine", Ports: []uint32{8080}, Payload: []byte("x"),
	}))

	_, _, err := LoadFingerprintPack(path, pub)
	if !errors.Is(err, ErrPackUnsigned) {
		t.Fatalf("err = %v, want ErrPackUnsigned", err)
	}
}

// TestTheSignatureIsCheckedBeforeThePayloadIsParsed.
//
// Parsing attacker-controlled JSON is a smaller surface than parsing it and then
// acting on it, and it is not nothing. A payload that is not JSON at all, under
// a signature that does not verify, must come back as a SIGNATURE failure — if
// it comes back as a format failure, the parse ran first.
func TestTheSignatureIsCheckedBeforeThePayloadIsParsed(t *testing.T) {
	pub, _ := testKey(t)
	_, other := testKey(t)
	path := writeRaw(t, other, []byte("this is not JSON at all"))

	_, _, err := LoadFingerprintPack(path, pub)
	if !errors.Is(err, ErrPackUnsigned) {
		t.Fatalf("err = %v, want ErrPackUnsigned — the payload was parsed before it was verified", err)
	}
}

// TestAPackFromTheFutureIsRefusedRatherThanReadBestEffort.
//
// A format change that added a field this build ignores would mean silently
// applying a rule that means something else now. The point of a signed corpus is
// that what runs is what was authored.
func TestAPackFromTheFutureIsRefusedRatherThanReadBestEffort(t *testing.T) {
	pub, priv := testKey(t)
	pack := validPack(enginewire.Probe{Name: "fine", Ports: []uint32{8080}, Payload: []byte("x")})
	pack.FormatVersion = PackFormatVersion + 1
	path := writePack(t, priv, pack)

	_, _, err := LoadFingerprintPack(path, pub)
	if !errors.Is(err, ErrPackMalformed) {
		t.Fatalf("err = %v, want ErrPackMalformed", err)
	}
}

// TestABuiltinProbeNameCannotBeRedefinedByAPack.
//
// The name is what an observation is traced by. A pack that could redefine
// `http-head` could change what those bytes are while the observation still
// named the probe an operator has read the source of.
func TestABuiltinProbeNameCannotBeRedefinedByAPack(t *testing.T) {
	corpus, _ := BuiltinCorpus()
	before := len(corpus.Probes)

	rejected := corpus.Merge(&FingerprintPack{
		PackID: "p", Version: "v", FormatVersion: PackFormatVersion,
		Probes: []enginewire.Probe{
			{Name: "http-head", Ports: []uint32{80}, Payload: []byte("EVIL")},
			{Name: "genuinely-new", Ports: []uint32{9999}, Payload: []byte("x")},
		},
	})

	if len(rejected) != 1 || !strings.Contains(rejected[0], "http-head") {
		t.Fatalf("rejections: %v", rejected)
	}
	if len(corpus.Probes) != before+1 {
		t.Errorf("probe count %d, want %d: exactly the new one added", len(corpus.Probes), before+1)
	}
	for _, p := range corpus.Probes {
		if p.Name == "http-head" && strings.Contains(string(p.Payload), "EVIL") {
			t.Fatal("the pack replaced a built-in probe's payload")
		}
	}
}

// TestARuleThatIsSoftAndNamesAProductIsRefused.
//
// Soft means "protocol known, product not". A rule claiming both is two
// different answers, and the engine resolves softness from the product it ends
// up with — so this would be a declaration the engine silently disagrees with.
func TestARuleThatIsSoftAndNamesAProductIsRefused(t *testing.T) {
	pub, priv := testKey(t)
	pack := validPack(enginewire.Probe{
		Name: "contradictory", Ports: []uint32{8080}, Payload: []byte("x"),
		Matches: []enginewire.Match{{
			Pattern: `^x`, Service: "http", Product: "nginx", Soft: true, Confidence: 0.9,
		}},
	})
	path := writePack(t, priv, pack)

	got, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Probes) != 0 {
		t.Error("a self-contradictory rule survived")
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "soft") {
		t.Errorf("rejections: %v", rejected)
	}
}

// TestZeroConfidenceIsRefusedRatherThanDefaulted.
//
// Zero is what an omitted field decodes to, and a rule firing at zero confidence
// is one ADR-014 will present as worthless. Guessing a confidence on the pack's
// behalf would invent evidence quality nobody authored.
func TestZeroConfidenceIsRefusedRatherThanDefaulted(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(enginewire.Probe{
		Name: "no-confidence", Ports: []uint32{8080}, Payload: []byte("x"),
		Matches: []enginewire.Match{{Pattern: `^x`, Service: "http"}},
	}))

	got, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Probes) != 0 || len(rejected) != 1 {
		t.Fatalf("probes=%d rejections=%v", len(got.Probes), rejected)
	}
}

// TestABadPackLeavesTheBuiltinCorpusAndReportsUpstream.
//
// ============================================================================
// Refusing to start would turn a content problem into an outage.
// ============================================================================
//
// ADR-019's requirement is not that a bad pack stops the process — it is that
// the refusal is not SILENT, because "the pack is not loaded, detection silently
// regresses, and nothing says so" is the failure it was written against. A scan
// point offline identifies nothing at all, which is strictly worse than one on
// the built-in set.
func TestABadPackLeavesTheBuiltinCorpusAndReportsUpstream(t *testing.T) {
	pub, _ := testKey(t)
	_, other := testKey(t)
	packPath := writePack(t, other, validPack())

	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}

	corpus, status := LoadCorpus(Config{
		FingerprintPackPath: packPath, FingerprintKeyPath: keyPath,
	}, quietLogger())

	if len(corpus.BannerMatches) == 0 || len(corpus.Probes) == 0 {
		t.Fatal("a refused pack left the scan point with no corpus at all")
	}
	if status.GetState() != scanpointv1.RulePackState_REJECTED_SIGNATURE {
		t.Errorf("state = %v, want REJECTED_SIGNATURE", status.GetState())
	}
	if status.GetDetail() == "" {
		t.Error("the refusal carries no detail, so an operator cannot tell why")
	}
}

// TestAProbeThatSendsNothingIsRefused.
//
// A probe with no payload and no handshake is a connect, and the engine already
// connects to every port it examines. Accepting one buys a second full
// connection per port per host for nothing.
//
// A TLS probe with no payload is a different thing and is allowed: `tls-hello`
// handshakes and sends no application data, because the certificate is what it
// is buying.
func TestAProbeThatSendsNothingIsRefused(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(
		enginewire.Probe{Name: "empty", Ports: []uint32{8080}},
		enginewire.Probe{Name: "handshake-only", Ports: []uint32{8443}, TLS: true},
	))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Probes) != 1 || pack.Probes[0].Name != "handshake-only" {
		t.Fatalf("surviving probes: %+v", pack.Probes)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "empty") {
		t.Errorf("rejections: %v", rejected)
	}
}

// TestNoPackConfiguredIsStillReported.
//
// Offline import means Core never knows what is live unless it is told, so
// "running on built-ins" has to travel too. Otherwise a scan point that has
// forgotten its pack is indistinguishable from one that never had one.
func TestNoPackConfiguredIsStillReported(t *testing.T) {
	corpus, status := LoadCorpus(Config{}, quietLogger())
	if len(corpus.Probes) == 0 {
		t.Fatal("no built-in probes")
	}
	if status == nil || status.GetDetail() == "" {
		t.Fatal("nothing reported for a scan point with no pack")
	}
	if status.GetState() == scanpointv1.RulePackState_LOADED {
		t.Error("state is LOADED with no pack loaded")
	}
}

// TestAGoodPackLoadsAndItsProbesSurvive.
//
// The other direction, so these tests are not only about refusal.
func TestAGoodPackLoadsAndItsProbesSurvive(t *testing.T) {
	pub, priv := testKey(t)
	pack := validPack(enginewire.Probe{
		Name: "redis-info", Ports: []uint32{6379}, Payload: []byte("PING\r\n"),
		Matches: []enginewire.Match{{Pattern: `^\+PONG`, Service: "redis", Product: "Redis", Confidence: 0.9}},
	})
	pack.BannerMatches = []enginewire.Match{
		{Pattern: `^RFB (?P<version>[\d.]+)`, Service: "vnc", Soft: true, Confidence: 0.8},
	}
	packPath := writePack(t, priv, pack)

	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	corpus, status := LoadCorpus(Config{
		FingerprintPackPath: packPath, FingerprintKeyPath: keyPath,
	}, quietLogger())

	if status.GetState() != scanpointv1.RulePackState_LOADED {
		t.Fatalf("state = %v (%s)", status.GetState(), status.GetDetail())
	}
	if status.GetPackId() != "cvap-fingerprint" || status.GetVersion() != "2026.09.1" {
		t.Errorf("pack identity not reported: %q %q", status.GetPackId(), status.GetVersion())
	}
	var found bool
	for _, p := range corpus.Probes {
		if p.Name == "redis-info" {
			found = true
		}
	}
	if !found {
		t.Error("the pack's probe did not reach the corpus")
	}
	// The built-in banner rules come FIRST, so a pack extends the tail and
	// cannot shadow a reviewed rule.
	if corpus.BannerMatches[len(corpus.BannerMatches)-1].Service != "vnc" {
		t.Error("the pack's banner rule is not at the tail of the list")
	}
}

// TestTheBuiltinCorpusObeysItsOwnPolicy.
//
// The policy is written for packs and the built-in set WAS exempt from it by
// construction — exactly the gap where a probe to 9100 would go unnoticed. It is
// no longer exempt: BuiltinCorpus applies the same filter at load. This asserts
// the filter removes nothing, which is a stronger claim than "it is applied",
// because a built-in silently dropped is under-identification.
func TestTheBuiltinCorpusObeysItsOwnPolicy(t *testing.T) {
	corpus, rejected := BuiltinCorpus()
	if len(rejected) > 0 {
		t.Fatalf("the built-in corpus violates the policy a pack is held to:\n  %s",
			strings.Join(rejected, "\n  "))
	}
	if len(corpus.Probes) != len(ProbeCorpus()) {
		t.Errorf("BuiltinCorpus kept %d of %d probes and reported no rejection",
			len(corpus.Probes), len(ProbeCorpus()))
	}
}

// TestAProbeGrowsWhenItsPlaceholderIsSubstitutedAndTheBoundKnowsIt.
//
// ============================================================================
// The bound was on the AUTHORED bytes, and substitution happens after it.
// ============================================================================
//
// Found by a safety audit driving a 510-byte probe of 51 `{{target}}`
// placeholders through the policy and capturing 867 bytes on the wire against a
// v4-mapped address — ~1989 against a full IPv6 target, four times the bound.
// Every check in this package runs before the engine rewrites the payload, so a
// bound on what the pack authored bounds the wrong thing.
func TestAProbeGrowsWhenItsPlaceholderIsSubstitutedAndTheBoundKnowsIt(t *testing.T) {
	pub, priv := testKey(t)
	payload := []byte(strings.Repeat(ProbeTargetPlaceholder, 51))
	if len(payload) > MaxProbePayload {
		t.Fatalf("the fixture is %d bytes, which the authored-size bound would already "+
			"refuse; this test would then pass for the wrong reason", len(payload))
	}
	path := writePack(t, priv, validPack(enginewire.Probe{
		Name: "grow-past-bound", Ports: []uint32{8080}, Payload: payload,
		Matches: []enginewire.Match{{Pattern: `^x`, Service: "http", Confidence: 0.9}},
	}))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Probes) != 0 {
		t.Error("a probe that grows past the payload bound on substitution survived")
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "after target substitution") {
		t.Errorf("rejections: %v", rejected)
	}
}

// TestAPortOutsideTheRangeIsRefusedRatherThanTruncatedTwoProcessesAway.
//
// The engine's process shell drops an out-of-range port rather than truncating,
// so this is inert today. Refused here anyway: the safety of a denylist that
// compares numbers must not rest on a narrowing conversion elsewhere behaving
// one way rather than the other. 74636 truncates to 9100.
func TestAPortOutsideTheRangeIsRefusedRatherThanTruncatedTwoProcessesAway(t *testing.T) {
	pub, priv := testKey(t)
	path := writePack(t, priv, validPack(enginewire.Probe{
		Name: "truncates-to-9100", Ports: []uint32{74636}, Payload: []byte("\r\n"),
		Matches: []enginewire.Match{{Pattern: `^x`, Service: "x", Confidence: 0.9}},
	}))

	pack, rejected, err := LoadFingerprintPack(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Probes) != 0 || len(rejected) != 1 {
		t.Fatalf("probes=%d rejections=%v", len(pack.Probes), rejected)
	}
	var overflowing uint32 = 74636
	if uint16(overflowing) != 9100 {
		t.Fatalf("this test's premise is that narrowing 74636 to uint16 gives 9100, got %d",
			uint16(overflowing))
	}
}

// TestEveryBuiltinPatternCompilesAndNamesItsCaptures.
//
// A pattern that does not compile is a rule that silently matches nothing, and
// the built-in set is the one nothing else checks.
func TestEveryBuiltinPatternCompilesAndNamesItsCaptures(t *testing.T) {
	known := map[string]bool{"version": true, "product": true, "info": true}
	check := func(where string, ms []enginewire.Match) {
		for i, m := range ms {
			re, err := regexp.Compile(m.Pattern)
			if err != nil {
				t.Errorf("%s[%d] %q: %v", where, i, m.Pattern, err)
				continue
			}
			for _, name := range re.SubexpNames() {
				if name != "" && !known[name] {
					t.Errorf("%s[%d] captures %q, which nothing lifts into the observation",
						where, i, name)
				}
			}
			if m.Service == "" {
				t.Errorf("%s[%d] names no service", where, i)
			}
		}
	}
	check("banner", BuiltinBannerMatches())
	for _, p := range ProbeCorpus() {
		check("probe "+p.Name, p.Matches)
	}
}

// TestThePlaceholderIsTheSameStringInTheEngines.
//
// The engines hold their own copy of the literal, because internal/enginewire is
// the contract between the two and this package is not on the engine import
// allowlist. A silent divergence would send `Host: {{target}}` to a real server
// — a request naming a host nobody authorised, which is the failure the
// placeholder exists to prevent.
func TestThePlaceholderIsTheSameStringInTheEngines(t *testing.T) {
	for _, f := range []string{
		"../engines/discovery/discovery.go",
		"../engines/fingerprint/fingerprint.go",
	} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), `"`+ProbeTargetPlaceholder+`"`) {
			t.Errorf("%s does not use the placeholder %q that the corpus embeds",
				f, ProbeTargetPlaceholder)
		}
	}
}

// TestTheEngineDenylistMatchesTheRuntimes.
//
// ============================================================================
// The engine holds its own copy, and a second site that quietly permits what
// the first refuses is worse than no second site at all.
// ============================================================================
//
// A safety audit drove a hand-written job into the fingerprint engine's stdin —
// bypassing this runtime entirely — and captured `@PJL INFO ID` arriving at port
// 9100. The engine now withholds those probes itself, from a compiled-in copy of
// this list, because internal/scanpoint is not on the engine import allowlist and
// putting it there would hand an engine this package's whole surface.
//
// The test lives HERE rather than beside the engine because it needs `os` to read
// the other file, and `os` is precisely what the engine allowlist refuses — the
// guard fired when this was written the other way round, which is the guard
// working.
func TestTheEngineDenylistMatchesTheRuntimes(t *testing.T) {
	src, err := os.ReadFile("../engines/fingerprint/fingerprint.go")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var nonInertPorts = map\[uint16\]bool\{(.*?)\n\}`).
		FindStringSubmatch(string(src))
	if block == nil {
		t.Fatal("could not find the engine's nonInertPorts; this test has stopped checking anything")
	}
	got := map[uint32]bool{}
	for _, m := range regexp.MustCompile(`(\d+):\s*true`).FindAllStringSubmatch(block[1], -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		got[uint32(n)] = true
	}
	if len(got) == 0 {
		t.Fatal("parsed no ports out of the engine's denylist")
	}
	for p := range nonInertPorts {
		if !got[p] {
			t.Errorf("port %d is on this runtime's denylist and not on the engine's", p)
		}
	}
	for p := range got {
		if _, ok := nonInertPorts[p]; !ok {
			t.Errorf("port %d is on the engine's denylist and not on this runtime's", p)
		}
	}
}
