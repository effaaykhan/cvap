package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Token format and lifetime.
const (
	// TokenPrefix identifies a CVAP enrollment token on sight.
	//
	// The trade, stated: a prefix tells whoever finds a leaked token what it is.
	// It also lets GitHub and GitLab secret scanning match it, lets us grep our
	// own logs and ticket systems for one, and lets a scan point reject an
	// obviously-wrong paste before spending a round trip. ghp_ and AKIA make the
	// same trade for the same reasons. Detection beats obscurity here, because
	// the token is short-lived and single-use and the leak is what matters.
	TokenPrefix = "cvapent_"

	// tokenEntropyBytes is 256 bits from crypto/rand. Enough that the stored
	// SHA-256 needs no password-hashing KDF: there is nothing to brute-force.
	tokenEntropyBytes = 32

	// DefaultTTL is long enough for an operator to issue a token and install a
	// scan point in a change window; short enough that one pasted into a ticket
	// expires before the ticket is closed.
	DefaultTTL = 24 * time.Hour

	// MaxTTL is also a CHECK constraint in migration 0017. A token valid for a
	// month is the shape of the long-lived shared secret ADR-018 rejected.
	MaxTTL = 7 * 24 * time.Hour
)

var (
	ErrTokenMalformed = errors.New("enrollment: token is malformed")
	ErrTTLTooLong     = fmt.Errorf("enrollment: TTL exceeds the %s maximum", MaxTTL)
)

// PlaintextToken carries an enrollment token in memory.
//
// ============================================================================
// This type MUST NOT render its value. Every rendering path is closed.
// ============================================================================
//
// A bearer credential: whoever holds one obtains a fleet identity. It must never
// reach a log, an error string, or a gRPC status (ADR-020, and the contract
// comment on EnrollRequest.enrollment_token).
//
// internal/logging redacts on the attribute KEY and cannot see inside a value a
// type renders for itself, so the type has to be safe on its own. Implementing
// nothing is NOT the safe choice, and that is the trap: a bare struct with an
// unexported string field still prints its contents under %v, because fmt
// reaches unexported fields by reflection.
//
// So all four paths are closed deliberately:
//
//	Format()       every fmt verb. fmt.handleMethods consults Stringer only for
//	               %v %s %q %x %X; under %d, %b, %c or any other verb it falls
//	               through to reflection. Formatter is consulted before the verb
//	               switch, so this is what makes those verbs print [REDACTED]
//	               rather than the field's address.
//	String()       kept for callers that ask for a string directly
//	GoString()     %#v via GoStringer
//	LogValue()     log/slog, including slog.Any
//	MarshalJSON()  encoding/json, and anything built on it
//	Reveal()       the ONLY way out, named to be conspicuous and greppable
//
// # Why the field is a func
//
// The second thing the review found, and the reason this is not just a string.
// A PlaintextToken held in an UNEXPORTED field of some other struct is rendered
// by reflection, and fmt never calls any method on it: reflect.Value.CanInterface
// is false there, so String, GoString and Format are all skipped and the raw
// value prints. Nothing catches that — not go vet, not check_secret_logging.py.
// A handler or issuer caching a token in a private field is the realistic shape.
//
// A func value has no rendering: reflection prints it as an address at every
// verb, in every position, including an unexported containing field. That is the
// only structural fix — every other approach depends on a method being called,
// and in this position none is.
//
// Measured, rather than assumed, because the ordering matters and the obvious
// reading is wrong:
//
//	string field, %d          {%!d(string=cvapent_...)}   LEAK
//	string field, unexported  {{cvapent_...}}             LEAK
//	func field,   %d          {4824512}                   no leak
//	func field,   unexported  {{0x499dc0}}                no leak
//
// So the FUNC FIELD is the fix, and Format is hygiene on top of it: with the
// func field the verbs are already safe, and Format only makes them legible.
// Both stay — Format is also what catches someone changing the field back to a
// string, which is the likely future mistake.
//
// .github/scripts/check_secret_logging.py fails the build if Reveal() reaches a
// formatting call, and token_test.go enumerates the verbs rather than asserting
// the property in a comment. Both of the holes above were found by widening that
// enumeration, which is the argument for it.
type PlaintextToken struct {
	v func() string
}

// NewToken mints a token. The plaintext exists only in the returned value.
func NewToken() (PlaintextToken, error) {
	b := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return PlaintextToken{}, fmt.Errorf("enrollment: generate token: %w", err)
	}
	return newToken(TokenPrefix + base64.RawURLEncoding.EncodeToString(b)), nil
}

func newToken(v string) PlaintextToken {
	return PlaintextToken{v: func() string { return v }}
}

// ParseToken accepts a token from the wire.
//
// Shape is validated before anything else so a malformed paste costs a string
// comparison rather than a database round trip. It is NOT authentication: a
// well-formed token is still unknown until the hash resolves.
func ParseToken(s string) (PlaintextToken, error) {
	if !strings.HasPrefix(s, TokenPrefix) {
		return PlaintextToken{}, ErrTokenMalformed
	}
	body := strings.TrimPrefix(s, TokenPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) != tokenEntropyBytes {
		// The decode error is discarded rather than wrapped: it can echo the
		// token's own bytes, and this error travels to a caller.
		return PlaintextToken{}, ErrTokenMalformed
	}
	return newToken(s), nil
}

// Hash is what the database stores and looks up. SHA-256 of the token as it
// appears on the wire, prefix included.
func (t PlaintextToken) Hash() []byte {
	sum := sha256.Sum256([]byte(t.reveal()))
	return sum[:]
}

func (t PlaintextToken) reveal() string {
	if t.v == nil {
		return ""
	}
	return t.v()
}

// Reveal returns the token itself.
//
// The only accessor, and named so that every call site says out loud what it is
// doing. There are exactly two legitimate callers: the operator API returning a
// freshly issued token once, and a test. Anything else is a defect.
func (t PlaintextToken) Reveal() string { return t.reveal() }

// IsZero reports whether this is the zero value rather than a real token.
func (t PlaintextToken) IsZero() bool { return t.v == nil }

// Redacted is what every rendering path returns.
const Redacted = "[REDACTED]"

// Format covers every verb, because Stringer does not.
//
// fmt.handleMethods consults Formatter first and unconditionally; it consults
// Stringer only for %v %s %q %x %X. Without this, %d on a token prints
// {%!d(string=cvapent_...)}.
func (t PlaintextToken) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, Redacted)
}

func (t PlaintextToken) String() string { return Redacted }

// GoString closes %#v, which ignores String entirely: fmt looks for GoStringer
// and otherwise renders the struct by reflection, unexported fields included.
func (t PlaintextToken) GoString() string {
	return "enrollment.PlaintextToken{" + Redacted + "}"
}

func (t PlaintextToken) LogValue() slog.Value { return slog.StringValue(Redacted) }

func (t PlaintextToken) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Redacted + `"`), nil
}

// ExpiryFor validates a requested TTL and returns the resulting expiry.
//
// The cap is enforced here and again as a CHECK constraint in migration 0017.
// Two places on purpose: this one produces a decent error for an operator, and
// the constraint holds for anything that reaches the table another way.
func ExpiryFor(now time.Time, ttl time.Duration) (time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return time.Time{}, ErrTTLTooLong
	}
	return now.Add(ttl), nil
}
