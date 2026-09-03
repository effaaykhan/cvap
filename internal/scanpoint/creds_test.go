package scanpoint_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/logging"
	"github.com/effaaykhan/cvap/internal/scanpoint"
)

const secret = "s3cr3t-domain-admin-password-not-real"

// decimalPrefix is how the first bytes of the secret render under %v on a
// []byte — the form a leak would take if the material sat in a byte field
// rather than behind a func.
var decimalPrefix = fmt.Sprintf("%v", []byte(secret)[:8])

func newCred() *scanpoint.Credential {
	return scanpoint.NewCredential("g-1", "j-1", "RAW_SECRET",
		[]string{"192.0.2.0/24"}, time.Now().Add(time.Minute), []byte(secret))
}

// TestCredentialNeverRenders is the ADR-038 enumeration, mirroring
// enrollment.TestPlaintextTokenNeverRenders.
//
// That enumeration is the test that found both of ADR-035's gaps, and ADR-038
// requires every new secret-holding type to repeat it. This is the second
// instance. The unexported-field cases are the ones nothing else catches:
// reflect.Value.CanInterface is false there, so fmt calls NO method on the value
// and prints it directly — which is why the material lives behind func fields
// rather than in a []byte one.
func TestCredentialNeverRenders(t *testing.T) {
	c := newCred()

	check := func(t *testing.T, path, rendered string) {
		t.Helper()
		if strings.Contains(rendered, secret) {
			t.Errorf("%s rendered the credential in full: %s", path, rendered)
		}
		// A prefix leaking is a leak. Byte-slice rendering prints DECIMALS, so
		// the numeric form has to be checked too: %v on a []byte field prints
		// [115 51 ...], which contains no substring of the text and would slip
		// past a search for the secret itself.
		if strings.Contains(rendered, decimalPrefix) {
			t.Errorf("%s rendered the credential as bytes: %s", path, rendered)
		}
	}

	check(t, "%v", fmt.Sprintf("%v", c))
	//nolint:staticcheck // deliberately exercising the %s verb, not String()
	check(t, "%s", fmt.Sprintf("%s", c))
	check(t, "%+v", fmt.Sprintf("%+v", c))
	check(t, "%#v", fmt.Sprintf("%#v", c))
	check(t, "String()", c.String())
	check(t, "GoString()", c.GoString())

	// Dereferenced, which is how a careless log line would take it.
	check(t, "deref %v", fmt.Sprintf("%v", *c))
	check(t, "deref %+v", fmt.Sprintf("%+v", *c))

	j, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	check(t, "json.Marshal", string(j))

	type wrapper struct {
		Cred *scanpoint.Credential
		Note string
	}
	check(t, "struct %v", fmt.Sprintf("%v", wrapper{Cred: c, Note: "n"}))
	check(t, "struct %+v", fmt.Sprintf("%+v", wrapper{Cred: c, Note: "n"}))
	jw, err := json.Marshal(wrapper{Cred: c, Note: "n"})
	if err != nil {
		t.Fatalf("json wrapper: %v", err)
	}
	check(t, "json.Marshal(struct)", string(jw))

	// Through the project's handler, and through a bare one. The bare handler is
	// the case that matters: it has no redaction and the type must protect
	// itself.
	var buf bytes.Buffer
	logging.New(&buf, logging.Options{Level: slog.LevelDebug}).Info("granted", slog.Any("cred", c))
	check(t, "logging.New", buf.String())

	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("granted",
		slog.Any("cred", c), slog.String("other", "x"))
	check(t, "bare slog.JSONHandler", buf.String())

	// Every verb, in every position.
	for _, verb := range []string{
		"%v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%t", "%p", "%T",
	} {
		format := verb // non-constant, so go vet does not pre-empt the check
		check(t, "verb "+verb, fmt.Sprintf(format, c))
		check(t, "verb "+verb+" (value)", fmt.Sprintf(format, *c))
		check(t, "verb "+verb+" (slice)", fmt.Sprintf(format, []*scanpoint.Credential{c}))
		check(t, "verb "+verb+" (value slice)", fmt.Sprintf(format, []scanpoint.Credential{*c}))
		check(t, "verb "+verb+" (map)", fmt.Sprintf(format, map[string]*scanpoint.Credential{"k": c}))
	}

	// Held in an UNEXPORTED field, by pointer and by value. fmt calls no method
	// here, so only the field types protect the value.
	type privateHolder struct {
		cred *scanpoint.Credential
		val  scanpoint.Credential
		note string
	}
	held := privateHolder{cred: c, val: *c, note: "n"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		format := verb
		check(t, "unexported field "+verb, fmt.Sprintf(format, held))
		check(t, "unexported field "+verb+" (pointer)", fmt.Sprintf(format, &held))
	}
}

// TestZeroiseErasesTheBackingArray is ADR-020's requirement, asserted against the
// array rather than against a flag.
//
// The reason ADR-038 exists: a Go string cannot do this at all, so under
// ADR-035's literal wording JobTerminal.credentials_zeroised could only ever
// have been an assertion. Core raises an audit event when that flag is absent,
// which would have made it a lie the audit log records as a fact.
func TestZeroiseErasesTheBackingArray(t *testing.T) {
	material := []byte(secret)
	c := scanpoint.NewCredential("g", "j", "RAW_SECRET", nil, time.Now(), material)

	if !bytes.Equal(c.Reveal(), []byte(secret)) {
		t.Fatal("Reveal did not return the material")
	}
	if c.Zeroised() {
		t.Fatal("a live credential reports itself zeroised")
	}

	c.Zeroise()

	if c.Reveal() != nil {
		t.Error("Reveal returned something after Zeroise")
	}
	if !c.Zeroised() {
		t.Error("Zeroised() is false after Zeroise()")
	}
	// The array the caller handed over — the same one the decoded protobuf
	// message points at — is erased in place. A copy would have left the secret
	// somewhere Zeroise cannot reach, which is why NewCredential takes
	// ownership rather than copying.
	for i, b := range material {
		if b != 0 {
			t.Fatalf("byte %d of the original array survived Zeroise: %q", i, material)
		}
	}
}

// TestZeroiseIsIdempotentAndSafeOnZero. It is called from deferred cleanup on
// paths that race — ADR-020 wants zeroisation on completion, lease loss and
// abort, and a job can hit two of those at once.
func TestZeroiseIsIdempotentAndSafeOnZero(t *testing.T) {
	c := newCred()
	c.Zeroise()
	c.Zeroise()
	c.Zeroise()

	var zero scanpoint.Credential
	zero.Zeroise()
	if zero.Reveal() != nil {
		t.Error("the zero Credential revealed something")
	}
	if !zero.Zeroised() {
		t.Error("the zero Credential does not report itself zeroised")
	}
	// Non-constant, so go vet does not pre-empt the check: a value Credential
	// implements no methods (they are on the pointer), so this is the pure
	// reflection path over func fields.
	zeroFormat := "%v %s %d %#v %x"
	//nolint:staticcheck // deliberately exercising the verbs on a value with no methods
	out := fmt.Sprintf(zeroFormat, zero, zero, zero, zero, zero)
	if strings.Contains(out, secret) || strings.Contains(out, decimalPrefix) {
		t.Errorf("the zero Credential rendered a secret it never held: %s", out)
	}

	// A nil holder is the "no credentials were issued for this job" case, which
	// is every job today. It must report zeroised: JobTerminal asserts the
	// invariant held, and for a job that held nothing it did.
	var nilCred *scanpoint.Credential
	if !nilCred.Zeroised() {
		t.Error("a nil Credential does not report itself zeroised")
	}
	if nilCred.Reveal() != nil {
		t.Error("a nil Credential revealed something")
	}
	nilCred.Zeroise()
}
