// Package credential is the one place CVAP hashes and verifies operator
// passwords.
//
// It was extracted from internal/control/api when cvap-cli's bootstrap command
// needed to write the first admin's password verifier: a shipped binary that
// writes a hash the operator API must later accept cannot carry its own second
// copy of the argon2id encoder, because two encoders drift and the drift shows
// up as every password being wrong. There is exactly one encoder, here, and both
// the API and the CLI call it.
//
// The PHC string is self-describing — m, t, p and the key length travel in it —
// so Verify reads the STORED parameters and verifies against those, and a hash
// written by an older build (or by a differently-tuned caller) still verifies,
// flagging needsRehash so it is upgraded at the one moment the plaintext is in
// hand. That is what makes a single source safe: the format, not a shared
// constant, is the contract.
package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — the cost a NEW hash is written with.
//
// RFC 9106's second recommended configuration for memory and passes — 64 MiB,
// three — chosen over the first (2 GiB) because Core handles several logins at
// once and 2 GiB per verification is a denial of service against ourselves.
//
// **One lane, not the RFC's four**, and that is the deliberate departure.
// Parallelism inside a single hash lowers the latency of ONE verification and
// does not change the total work; the RFC's p=4 assumes a machine doing nothing
// else. Core is a server, and four lanes per hash meant each verification
// saturated four cores, so a handful of concurrent unauthenticated logins
// starved every other handler. Throughput and responsiveness are what matter
// here, and p=1 with the same memory and passes costs an attacker exactly as
// much per guess.
//
// Existing hashes verify unchanged: the parameters travel in the PHC string, so
// a row written with p=4 is decoded and verified with p=4.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// errMalformed is the single decode failure. It is unexported because a caller
// that could distinguish "bad variant" from "bad base64" learns nothing it can
// act on — a corrupt stored hash is a row to repair, whatever broke it.
var errMalformed = errors.New("credential: malformed password hash")

type params struct {
	memory  uint32
	time    uint32
	threads uint8
}

// Hash produces a PHC-format argon2id string for a new password.
func Hash(password string) (string, error) {
	// Random BYTES, not the first sixteen characters of a base64 string.
	//
	// An earlier version sliced a base64 token: sixteen of those characters
	// carry 96 bits of entropy, not the 128 the length implies. Nothing about
	// the code said so, which is what made it worth fixing rather than
	// documenting.
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("credential: generating a salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encode(salt, key), nil
}

// Verify checks a password against a stored PHC string.
//
// Returns needsRehash when the stored parameters are weaker than this build's,
// so an old hash is upgraded at the one moment the plaintext is available.
func Verify(phc, password string) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decode(phc)
	if err != nil {
		return false, false, err
	}
	// decode bounds len(want) to [16, 1024], so the conversion cannot overflow.
	// Verifying against the STORED length rather than argonKeyLen is what lets a
	// hash written by an older build still verify.
	// #nosec G115 -- bounded by decode
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	// threads is deliberately NOT compared. It is a latency knob rather than a
	// strength one — total work is memory times passes — so a hash with more
	// lanes is not stronger and one with fewer is not weaker, and rehashing on
	// that axis would rewrite every row for nothing.
	weaker := p.time < argonTime || p.memory < argonMemory || len(want) < argonKeyLen
	return true, weaker, nil
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func encode(salt, key []byte) string {
	return strings.Join([]string{
		"", "argon2id", "v=" + strconv.Itoa(argon2.Version),
		"m=" + strconv.Itoa(argonMemory) + ",t=" + strconv.Itoa(argonTime) + ",p=" + strconv.Itoa(argonThreads),
		b64(salt), b64(key),
	}, "$")
}

// PHC string encoding for argon2id.
//
// Written out rather than pulled in, because the format is six fields and the
// parsing is the security-relevant part: a decoder that accepted a $argon2i$ or
// $argon2d$ string and verified it with the id variant would compare a hash of
// one thing against a hash of another and, for i and d, return false forever —
// locking every account out at once. So the variant is checked, not assumed.
//
// decode parses $argon2id$v=19$m=...,t=...,p=...$salt$hash.
func decode(s string) (params, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	// Leading empty field from the initial $, then five more.
	if len(parts) != 6 || parts[0] != "" {
		return params{}, nil, nil, errMalformed
	}
	if parts[1] != "argon2id" {
		// Refused rather than attempted. See the file comment: verifying an
		// argon2i hash with the id variant fails every time, which presents as
		// every password being wrong.
		return params{}, nil, nil, fmt.Errorf("%w: variant %q is not argon2id", errMalformed, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params{}, nil, nil, errMalformed
	}
	if version != argon2.Version {
		return params{}, nil, nil, fmt.Errorf("%w: version %d, this build speaks %d", errMalformed, version, argon2.Version)
	}

	var p params
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return params{}, nil, nil, errMalformed
	}
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return params{}, nil, nil, errMalformed
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return params{}, nil, nil, errMalformed
		}
		switch k {
		case "m":
			p.memory = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return params{}, nil, nil, errMalformed
			}
			p.threads = uint8(n)
		default:
			return params{}, nil, nil, errMalformed
		}
	}
	// Bounded on BOTH sides, and the upper bound is the one that matters.
	//
	// Zero anywhere makes argon2.IDKey panic, which is a denial of service
	// reachable by one corrupt row. The upper bound closes the larger version of
	// the same hazard: m is a 32-bit value, so a stored hash carrying
	// m=4294967295 asks argon2 for FOUR TERABYTES at login. Nothing reachable
	// writes such a row today — Set is only ever called with Hash's output — but
	// Set takes an arbitrary string and the column's only check is that it starts
	// with $argon2id$, so the parser is where this has to be refused.
	//
	// Four times the current memory and ten passes leave room for the parameters
	// to be raised later without a migration, and are far below anything that
	// hurts.
	if p.memory == 0 || p.time == 0 || p.threads == 0 {
		return params{}, nil, nil, errMalformed
	}
	if p.memory > 4*argonMemory || p.time > 10 {
		return params{}, nil, nil, fmt.Errorf(
			"%w: parameters m=%d t=%d are beyond what this build will spend on one verification",
			errMalformed, p.memory, p.time)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return params{}, nil, nil, errMalformed
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params{}, nil, nil, errMalformed
	}
	// Bounded, and the bound is what makes the uint32 conversion in Verify safe
	// rather than merely unlikely to overflow. 16 bytes is below any output
	// length worth having; 1 KiB is far above one, and a stored hash longer than
	// that is a corrupt row rather than a strong configuration.
	if len(key) < 16 || len(key) > 1024 {
		return params{}, nil, nil, errMalformed
	}
	return p, salt, key, nil
}
