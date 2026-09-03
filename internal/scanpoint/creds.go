package scanpoint

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Redacted is what a Credential renders as, everywhere.
const Redacted = "[REDACTED]"

// Credential is job-scoped credential material, held in memory and nowhere else.
//
// ============================================================================
// Two func fields and no byte field. That is the control, not the methods.
// ============================================================================
//
// ADR-038 (superseding ADR-035): a secret lives in a func-typed field, of a type
// that can be erased in place. A func value has no rendering — reflection prints
// an address at every verb, in every position, including an unexported field of
// another struct, which is the one position where no method of ours can run. A
// []byte field would print its contents there; a string field would too, and
// could not be zeroised at all.
//
// So the bytes are owned by a closure and reached only through reveal(), and the
// same closure variable is captured by zeroise(). Nothing on this struct holds
// the material directly, which is why %v on a Credential — or on something that
// embeds one privately — cannot leak it even with every method removed.
//
// ADR-020 requires zeroisation on job completion, lease loss and abort. Zeroise
// overwrites the backing array, so a copy of the process's memory taken
// afterwards does not contain the secret at that address. It is best-effort and
// says so: the gRPC receive buffer and the decoded protobuf message held the
// same bytes on the way in, and a garbage collector that moved the allocation
// before the overwrite leaves the original wherever it was. This is one layer —
// the others are that credentials never reach an engine process (ADR-027), never
// touch disk, and live only for the job.
//
// A Credential takes OWNERSHIP of the slice it is given. The caller must not
// retain it: the whole point is that one array holds the material and this type
// knows where it is. Taking the protobuf field directly rather than copying is
// deliberate — it means Zeroise also erases the decoded message's copy, and one
// fewer copy exists to miss.
type Credential struct {
	// A POINTER to the mutex, not a value, so that copying a Credential is
	// legal and means what it should. A sync.Mutex field makes every copy a
	// vet error, which would push the enumeration test below into testing only
	// the shapes that happen to compile — and a value held in an unexported
	// field is one of the shapes ADR-038 most wants covered. A copy shares the
	// mutex and the closures, so it is the same credential: zeroising through
	// either erases the one array, which is the only correct reading.
	mu *sync.Mutex

	// reveal returns the material, or nil once zeroised. Nil on the zero value.
	reveal func() []byte
	// zeroise overwrites the array reveal closes over.
	zeroise func()

	// Non-secret, and deliberately renderable: an operator debugging a grant
	// needs to see which grant, of what kind, scoped to what, expiring when.
	GrantID string
	JobID   string
	Kind    string
	Scope   []string
	Expires time.Time
}

// NewCredential takes ownership of material.
func NewCredential(grantID, jobID, kind string, scope []string, expires time.Time, material []byte) *Credential {
	buf := material
	return &Credential{
		mu:      new(sync.Mutex),
		reveal:  func() []byte { return buf },
		zeroise: func() { clear(buf); buf = nil },
		GrantID: grantID,
		JobID:   jobID,
		Kind:    kind,
		Scope:   append([]string(nil), scope...),
		Expires: expires,
	}
}

// Reveal is the only accessor. It returns nil after Zeroise and on the zero
// value.
//
// The returned slice is the live array, not a copy: a copy would be a second
// place the secret exists that Zeroise cannot reach. Callers must not retain it
// past the call that needed it.
func (c *Credential) Reveal() []byte {
	if c == nil {
		return nil
	}
	if c.mu != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	if c.reveal == nil {
		return nil
	}
	return c.reveal()
}

// Zeroise erases the material. Idempotent, and safe on the zero value, because
// it is called from deferred cleanup on paths that may already have run it —
// ADR-020 wants this on completion, lease loss AND abort, and those race.
func (c *Credential) Zeroise() {
	if c == nil {
		return
	}
	if c.mu != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	if c.zeroise != nil {
		c.zeroise()
	}
	c.reveal = nil
	c.zeroise = nil
}

// Zeroised reports whether the material is gone. This is what backs
// JobTerminal.credentials_zeroised, which Core audits when absent — so it must
// answer from the state of the holder rather than from a flag somebody set.
func (c *Credential) Zeroised() bool {
	if c == nil {
		return true // nothing was held, so nothing survives
	}
	if c.mu != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	return c.reveal == nil
}

// The redacting methods. Hygiene on top of the field types, per ADR-038: with
// func fields every verb is already safe, and these only make the output say so
// rather than print an address. They are also what catches someone changing a
// field back to a bare []byte, which is the likely future mistake.

func (c *Credential) String() string { return Redacted }

func (c *Credential) GoString() string { return "scanpoint.Credential" + Redacted }

func (c *Credential) LogValue() slog.Value { return slog.StringValue(Redacted) }

func (c *Credential) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// Format covers every verb, not the five that consult Stringer.
//
// fmt consults Stringer only for %v %s %q %x %X; under any other verb it falls
// through to reflection. go vet catches that for a constant format string and
// not for a computed one. The token type learned this from a security review
// rather than from reasoning about it (ADR-035), and the lesson transfers.
func (c *Credential) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte(Redacted))
	_ = verb
}
