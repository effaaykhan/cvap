package enrollment_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/logging"
)

// The token must not render itself through ANY path.
//
// Not one test per path as an afterthought: this is the whole protection. The
// contract marks enrollment_token debug_redact and protobuf-go ignores it; the
// key-based redactor cannot see inside a value a type renders for itself. So the
// type has to be safe alone, and "has to be" is worth proving rather than
// asserting.
//
// Note what would happen WITHOUT String(): a bare struct with an unexported
// string field prints its contents under %v, because fmt reaches unexported
// fields by reflection. Implementing nothing is not the safe option, which is
// why internal/logging/CLAUDE.md requires all three methods rather than
// forbidding them.
func TestPlaintextTokenNeverRenders(t *testing.T) {
	tok, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	secret := tok.Reveal()
	if !strings.HasPrefix(secret, enrollment.TokenPrefix) {
		t.Fatalf("token %q lacks the %q prefix", secret, enrollment.TokenPrefix)
	}

	contains := func(t *testing.T, path, rendered string) {
		t.Helper()
		if strings.Contains(rendered, secret) {
			t.Errorf("%s rendered the token in full: %s", path, rendered)
		}
		// The body alone leaking would be just as bad as the whole thing.
		body := strings.TrimPrefix(secret, enrollment.TokenPrefix)
		if strings.Contains(rendered, body) {
			t.Errorf("%s rendered the token body: %s", path, rendered)
		}
	}

	contains(t, "%v", fmt.Sprintf("%v", tok))
	// staticcheck S1025 says to call String() directly here, and in ordinary
	// code it would be right. This test exists to exercise the VERB: a future
	// change that drops String() would make %s fall back to reflection, which
	// is the leak being guarded against. Calling String() would test the method
	// and miss the path.
	//nolint:staticcheck // deliberately exercising the %s verb, not String()
	contains(t, "%s", fmt.Sprintf("%s", tok))
	contains(t, "%+v", fmt.Sprintf("%+v", tok))
	contains(t, "%#v", fmt.Sprintf("%#v", tok))
	contains(t, "String()", tok.String())

	// Inside a struct, which is how it actually travels.
	type wrapper struct {
		Token enrollment.PlaintextToken
		Note  string
	}
	contains(t, "struct %v", fmt.Sprintf("%v", wrapper{Token: tok, Note: "n"}))
	contains(t, "struct %+v", fmt.Sprintf("%+v", wrapper{Token: tok, Note: "n"}))

	j, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	contains(t, "json.Marshal", string(j))

	jw, err := json.Marshal(wrapper{Token: tok, Note: "n"})
	if err != nil {
		t.Fatalf("json wrapper: %v", err)
	}
	contains(t, "json.Marshal(struct)", string(jw))

	// slog, through the project's own handler, and through a bare one — the
	// bare handler is the case that matters, because it has no redaction and
	// the type must protect itself.
	var buf bytes.Buffer
	logging.New(&buf, logging.Options{Level: slog.LevelDebug}).Info("enrolling", slog.Any("token", tok))
	contains(t, "logging.New", buf.String())

	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("enrolling",
		slog.Any("token", tok), slog.String("other", "x"))
	contains(t, "bare slog.JSONHandler", buf.String())

	// And the one that catches a future refactor: %v on a slice of them.
	contains(t, "slice %v", fmt.Sprintf("%v", []enrollment.PlaintextToken{tok, tok}))

	// ------------------------------------------------------------------
	// EVERY verb, not the five that consult Stringer.
	// ------------------------------------------------------------------
	// fmt.handleMethods consults Stringer only for %v %s %q %x %X. Under any
	// other verb it falls through to reflection and prints the field. go vet
	// catches that for a constant format string but not a computed one, which
	// is why the type implements Formatter and why this loop exists.
	//
	// Found by a security review, not by reasoning about it — the argument for
	// enumerating rather than testing the obvious two.
	for _, verb := range []string{
		"%v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%t", "%p", "%T",
	} {
		format := verb // non-constant, so go vet does not pre-empt the check
		contains(t, "verb "+verb, fmt.Sprintf(format, tok))
		contains(t, "verb "+verb+" (pointer)", fmt.Sprintf(format, &tok))
		contains(t, "verb "+verb+" (slice)", fmt.Sprintf(format, []enrollment.PlaintextToken{tok}))
		contains(t, "verb "+verb+" (map)", fmt.Sprintf(format, map[string]enrollment.PlaintextToken{"k": tok}))
	}

	// ------------------------------------------------------------------
	// Held in an UNEXPORTED field of another struct.
	// ------------------------------------------------------------------
	// The case nothing else catches. reflect.Value.CanInterface is false for an
	// unexported field, so fmt calls NO method on the value — not String, not
	// GoString, not Format — and prints it directly. A handler or issuer caching
	// a token privately is the realistic shape, and it is why the field inside
	// PlaintextToken is a func rather than a string: a func has no rendering at
	// any verb, in any position.
	type privateHolder struct {
		tok  enrollment.PlaintextToken
		note string
	}
	held := privateHolder{tok: tok, note: "n"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
		format := verb
		contains(t, "unexported field "+verb, fmt.Sprintf(format, held))
		contains(t, "unexported field "+verb+" (pointer)", fmt.Sprintf(format, &held))
	}

	// The zero value must not panic on any of these paths.
	var zero enrollment.PlaintextToken
	if !zero.IsZero() {
		t.Error("the zero PlaintextToken does not report IsZero")
	}
	_ = fmt.Sprintf("%v %s %d %#v", zero, zero, zero, zero)
	_ = zero.Hash()
	if zero.Reveal() != "" {
		t.Error("the zero PlaintextToken revealed something")
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	good, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.ParseToken(good.Reveal()); err != nil {
		t.Fatalf("a freshly minted token did not parse: %v", err)
	}

	for _, bad := range []string{
		"",
		"nonsense",
		"cvapent_",                           // prefix, no body
		"cvapent_!!!!",                       // not base64url
		"cvapent_" + strings.Repeat("A", 10), // right alphabet, wrong length
		strings.TrimPrefix(good.Reveal(), enrollment.TokenPrefix),              // body without prefix
		"CVAPENT_" + strings.TrimPrefix(good.Reveal(), enrollment.TokenPrefix), // wrong case
	} {
		if _, err := enrollment.ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) accepted a malformed token", bad)
		}
	}
}

func TestTokensAreDistinctAndHashStably(t *testing.T) {
	a, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if a.Reveal() == b.Reveal() {
		t.Fatal("two freshly minted tokens are identical")
	}
	if bytes.Equal(a.Hash(), b.Hash()) {
		t.Fatal("two distinct tokens hash the same")
	}

	reparsed, err := enrollment.ParseToken(a.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Hash(), reparsed.Hash()) {
		t.Error("a token does not hash to the same value after a round trip through the wire form")
	}
	if len(a.Hash()) != 32 {
		t.Errorf("hash is %d bytes, want 32", len(a.Hash()))
	}
}

func TestExpiryCap(t *testing.T) {
	now := timeNow()
	if _, err := enrollment.ExpiryFor(now, enrollment.MaxTTL+1); err == nil {
		t.Error("a TTL beyond MaxTTL was accepted")
	}
	exp, err := enrollment.ExpiryFor(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := exp.Sub(now); got != enrollment.DefaultTTL {
		t.Errorf("zero TTL gave %s, want the %s default", got, enrollment.DefaultTTL)
	}
}
