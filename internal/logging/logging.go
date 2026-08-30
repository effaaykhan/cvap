package logging

import (
	"io"
	"log/slog"
	"strings"
)

// Placeholder replaces the value of any attribute whose key looks like it
// carries credential material.
const Placeholder = "[REDACTED]"

// sensitiveFragments are matched as substrings against a normalised attribute
// key (lowercased, with separators removed). The list is deliberately narrow:
// a fragment that over-matches gets weakened by the next person who needs to
// debug a redacted field, which is worse than a slightly shorter list.
//
// Note what is absent. Bare "key" would redact dedup_key, identity_key and
// host_key, which are load-bearing in this system and safe to log. "signature"
// would redact the rule pack signature digest, which ADR-019 expects in logs.
var sensitiveFragments = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"credential",
	"apikey",
	"accesskey",
	"privatekey",
	"signingkey",
	"authorization",
	"bearer",
	"material", // CredentialGrant.material
}

// normaliseKey lowercases a key and strips the separators that would otherwise
// let "api_key", "api-key" and "APIKey" evade the same fragment.
func normaliseKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch r {
		case '_', '-', '.', ' ':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String())
}

// IsSensitiveKey reports whether an attribute key looks like it carries
// credential material and must not have its value logged.
func IsSensitiveKey(key string) bool {
	n := normaliseKey(key)
	for _, frag := range sensitiveFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// Redact is a slog ReplaceAttr function. slog calls it for every non-group
// attribute, including attributes nested inside groups, so a credential does
// not escape by being one level down.
//
// It is a key-based control and cannot inspect what a type chooses to render:
// a struct whose String or MarshalJSON emits a secret will still emit it. That
// is why no type holding credential material may implement either
// (see internal/scanpoint/CLAUDE.md).
func Redact(_ []string, a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Placeholder)
	}
	return a
}

// Options configures the process logger.
type Options struct {
	Level     slog.Level
	AddSource bool
}

// New returns a JSON logger writing to w with redaction applied to every
// attribute.
func New(w io.Writer, opts Options) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       opts.Level,
		AddSource:   opts.AddSource,
		ReplaceAttr: Redact,
	}))
}
