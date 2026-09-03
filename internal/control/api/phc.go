package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PHC string encoding for argon2id.
//
// Written out rather than pulled in, because the format is six fields and the
// parsing is the security-relevant part: a decoder that accepted a $argon2i$ or
// $argon2d$ string and verified it with the id variant would compare a hash of
// one thing against a hash of another and, for i and d, return false forever —
// locking every account out at once. So the variant is checked, not assumed.

var errBadPHC = errors.New("api: malformed password hash")

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// decodePHC parses $argon2id$v=19$m=...,t=...,p=...$salt$hash.
func decodePHC(s string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	// Leading empty field from the initial $, then five more.
	if len(parts) != 6 || parts[0] != "" {
		return argonParams{}, nil, nil, errBadPHC
	}
	if parts[1] != "argon2id" {
		// Refused rather than attempted. See the file comment: verifying an
		// argon2i hash with the id variant fails every time, which presents as
		// every password being wrong.
		return argonParams{}, nil, nil, fmt.Errorf("%w: variant %q is not argon2id", errBadPHC, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, errBadPHC
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, fmt.Errorf("%w: version %d, this build speaks %d", errBadPHC, version, argon2.Version)
	}

	var p argonParams
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return argonParams{}, nil, nil, errBadPHC
	}
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return argonParams{}, nil, nil, errBadPHC
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return argonParams{}, nil, nil, errBadPHC
		}
		switch k {
		case "m":
			p.memory = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return argonParams{}, nil, nil, errBadPHC
			}
			p.threads = uint8(n)
		default:
			return argonParams{}, nil, nil, errBadPHC
		}
	}
	// Bounded on BOTH sides, and the upper bound is the one that matters.
	//
	// Zero anywhere makes argon2.IDKey panic, which is a denial of service
	// reachable by one corrupt row. The upper bound closes the larger version of
	// the same hazard: m is a 32-bit value, so a stored hash carrying
	// m=4294967295 asks argon2 for FOUR TERABYTES at login. Nothing reachable
	// writes such a row today — Credentials.Set is only ever called with
	// hashPassword's output — but Set takes an arbitrary string and the column's
	// only check is that it starts with $argon2id$, so the parser is where this
	// has to be refused.
	//
	// Four times the current memory and ten passes leave room for the parameters
	// to be raised later without a migration, and are far below anything that
	// hurts.
	if p.memory == 0 || p.time == 0 || p.threads == 0 {
		return argonParams{}, nil, nil, errBadPHC
	}
	if p.memory > 4*argonMemory || p.time > 10 {
		return argonParams{}, nil, nil, fmt.Errorf(
			"%w: parameters m=%d t=%d are beyond what this build will spend on one verification",
			errBadPHC, p.memory, p.time)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return argonParams{}, nil, nil, errBadPHC
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, errBadPHC
	}
	// Bounded, and the bound is what makes the uint32 conversion in
	// verifyPassword safe rather than merely unlikely to overflow. 16 bytes is
	// below any output length worth having; 1 KiB is far above one, and a
	// stored hash longer than that is a corrupt row rather than a strong
	// configuration.
	if len(key) < 16 || len(key) > 1024 {
		return argonParams{}, nil, nil, errBadPHC
	}
	return p, salt, key, nil
}
