package credential

import (
	"strings"
	"testing"
)

// mutate:subject internal/control/credential/phc.go
// mutate:test    ./internal/control/credential/ -run TestHashVerifyRoundTrip|TestVerifyRefusesAForeignVariant
//
// mutate:case    the argon2id variant guard accepts a foreign variant
// mutate:old     if parts[1] != "argon2id" {
// mutate:new     if parts[1] == "\x00" {
//
// The guard is why this package exists as prose rather than a library call: a
// decoder that let an $argon2i$ string through would verify it with the id
// variant, mismatch every time, and lock every account out at once. Removing the
// guard (the mutation above) leaves round-trip verification working — argon2id
// still verifies against argon2id — so ONLY the foreign-variant case kills it.

func TestHashVerifyRoundTrip(t *testing.T) {
	const pw = "correct horse battery staple"
	phc, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, rehash, err := Verify(phc, pw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("the correct password did not verify")
	}
	// A hash this build just wrote is at this build's parameters, so nothing to upgrade.
	if rehash {
		t.Error("a freshly written hash reported needsRehash")
	}

	ok, _, err = Verify(phc, "wrong")
	if err != nil {
		t.Fatalf("Verify(wrong): %v", err)
	}
	if ok {
		t.Error("a wrong password verified")
	}
}

// TestVerifyRefusesAForeignVariant is the case the variant guard exists for: a
// well-formed string that is argon2i, not argon2id, must be REFUSED (an error),
// never quietly treated as a mismatch — otherwise a stored argon2i row presents
// as a forgotten password rather than a corrupt one.
func TestVerifyRefusesAForeignVariant(t *testing.T) {
	phc, err := Hash("whatever")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	foreign := strings.Replace(phc, "$argon2id$", "$argon2i$", 1)
	if foreign == phc {
		t.Fatal("test setup: the variant field did not change")
	}
	if _, _, err := Verify(foreign, "whatever"); err == nil {
		t.Error("a foreign argon2i variant was not refused")
	}
}

// TestDecodeRefusesAnAbsurdCost covers the upper parameter bound — a stored hash
// asking for four terabytes at login is refused at decode, before argon2 is
// ever called with it. No mutation is declared here on purpose: bypassing the
// ceiling would let Verify reach argon2.IDKey with the absurd value, and the
// point of the bound is that that call never happens.
func TestDecodeRefusesAnAbsurdCost(t *testing.T) {
	phc, err := Hash("whatever")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	absurd := strings.Replace(phc, "m=65536", "m=4000000000", 1)
	if absurd == phc {
		t.Fatal("test setup: the memory field did not change")
	}
	if _, _, err := Verify(absurd, "whatever"); err == nil {
		t.Error("an absurd memory cost was not refused at decode")
	}
}
