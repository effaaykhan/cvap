// Package credsource resolves a credential profile's secret_ref — a scheme://
// pointer, never plaintext (ADR-020) — into the material Core places in a
// just-in-time CredentialGrant. The material is the caller's to hold briefly and
// zeroise; a Resolver never caches it and never logs it.
//
// Today one scheme is implemented, file://, which reads a key from the Core host's
// filesystem confined to a configured root. The Resolver seam is deliberate: vault://
// and kms:// slot in here without the dispatch producer that calls Resolve changing
// at all. An unknown scheme fails loudly rather than silently returning nothing — a
// credential that cannot be resolved must stop the job, not scan uncredentialed.
package credsource

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Resolver turns a secret_ref into credential material.
type Resolver interface {
	// Resolve returns the material for ref, or an error. The returned bytes are a
	// fresh slice the caller owns and should zeroise when done — a Resolver keeps
	// no reference to them.
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// ErrUnsupportedScheme is returned for a secret_ref whose scheme has no resolver.
var ErrUnsupportedScheme = errors.New("credsource: unsupported secret_ref scheme")

// SchemeResolver dispatches by URL scheme. It is the Resolver the producer holds;
// which backends it carries is a deployment decision, not the producer's.
type SchemeResolver struct {
	byScheme map[string]Resolver
}

// NewSchemeResolver builds a dispatcher from scheme->resolver pairs.
func NewSchemeResolver(byScheme map[string]Resolver) *SchemeResolver {
	m := make(map[string]Resolver, len(byScheme))
	for k, v := range byScheme {
		m[strings.ToLower(k)] = v
	}
	return &SchemeResolver{byScheme: m}
}

// Resolve dispatches ref to the backend registered for its scheme.
func (s *SchemeResolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("credsource: malformed secret_ref: %w", err)
	}
	r, ok := s.byScheme[strings.ToLower(u.Scheme)]
	if !ok {
		// Name the scheme, never the ref: keeping the error narrow avoids leaking
		// deployment layout into logs.
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedScheme, u.Scheme)
	}
	return r.Resolve(ctx, ref)
}

// FileResolver reads material from the Core host's filesystem, confined to Root so a
// secret_ref cannot walk to an arbitrary file. It is lab-grade key custody and says
// so: a production deployment points secret_ref at a real secret backend instead.
type FileResolver struct {
	// Root is the only directory a file:// ref may read under. A ref resolving
	// outside it (via .., a symlink, or an absolute path elsewhere) is refused.
	Root string
	// MaxBytes bounds the read: an SSH private key is a few KB, and an unbounded
	// read of an attacker-swapped path is a memory DoS against Core.
	MaxBytes int64
}

const defaultMaxSecretBytes = 1 << 20 // 1 MiB — generous for any key, still bounded.

// NewFileResolver confines reads to root (resolved to an absolute path).
func NewFileResolver(root string) (*FileResolver, error) {
	if root == "" {
		return nil, errors.New("credsource: file resolver needs a root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("credsource: file resolver root: %w", err)
	}
	return &FileResolver{Root: abs, MaxBytes: defaultMaxSecretBytes}, nil
}

// Resolve reads the file named by a file:// ref, refusing anything outside Root.
func (f *FileResolver) Resolve(_ context.Context, ref string) ([]byte, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("credsource: malformed file secret_ref: %w", err)
	}
	if u.Scheme != "file" {
		return nil, fmt.Errorf("%w: file resolver got %q", ErrUnsupportedScheme, u.Scheme)
	}
	// file:///etc/x -> Path "/etc/x"; file://host/x is rejected (a remote host is
	// not a local file, and honouring it would be a surprising escape).
	if u.Host != "" && u.Host != "localhost" {
		return nil, fmt.Errorf("credsource: file secret_ref must be local, got host %q", u.Host)
	}
	// Resolve symlinks before the containment check so a link inside Root pointing
	// out of it cannot escape. EvalSymlinks requires the file to exist, which is
	// the case we care about; a missing file is a plain read error here.
	// Errors below name the CAUSE and never the path: these messages land in
	// job.credential_refused audit detail and in Core's log, and a secret_ref
	// is Core's filesystem layout. os errors carry the path, so only their
	// underlying errno travels.
	resolved, err := filepath.EvalSymlinks(filepath.Clean(u.Path))
	if err != nil {
		return nil, fmt.Errorf("credsource: resolving secret path: %w", cause(err))
	}
	root, err := filepath.EvalSymlinks(f.Root)
	if err != nil {
		return nil, fmt.Errorf("credsource: resolving secret root: %w", cause(err))
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("credsource: secret_ref resolves outside the permitted root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("credsource: stat secret: %w", cause(err))
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credsource: secret_ref is not a regular file")
	}
	if f.MaxBytes > 0 && info.Size() > f.MaxBytes {
		return nil, fmt.Errorf("credsource: secret is %d bytes, over the %d cap", info.Size(), f.MaxBytes)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("credsource: reading secret: %w", cause(err))
	}
	return b, nil
}

// cause strips the path from an os error, keeping the errno.
func cause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}
