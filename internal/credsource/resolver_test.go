package credsource

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileResolverReadsUnderRoot(t *testing.T) {
	root := t.TempDir()
	want := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n")
	if err := os.WriteFile(filepath.Join(root, "key"), want, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewFileResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(context.Background(), "file://"+filepath.Join(root, "key"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch")
	}
}

func TestFileResolverRefusesEscape(t *testing.T) {
	root := t.TempDir()
	// A secret one level above the root must not be reachable via traversal.
	outside := filepath.Join(filepath.Dir(root), "outside-secret")
	if err := os.WriteFile(outside, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })
	r, err := NewFileResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	ref := "file://" + filepath.Join(root, "..", "outside-secret")
	if _, err := r.Resolve(context.Background(), ref); err == nil {
		t.Fatal("expected a traversal escape to be refused")
	}
}

func TestFileResolverRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-symlink-target")
	if err := os.WriteFile(outside, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r, _ := NewFileResolver(root)
	if _, err := r.Resolve(context.Background(), "file://"+link); err == nil {
		t.Fatal("expected a symlink pointing outside the root to be refused")
	}
}

func TestFileResolverEnforcesSizeCap(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	r, _ := NewFileResolver(root)
	r.MaxBytes = 1024
	if _, err := r.Resolve(context.Background(), "file://"+big); err == nil {
		t.Fatal("expected the size cap to refuse an oversized secret")
	}
}

func TestSchemeResolverUnknownSchemeFailsLoudly(t *testing.T) {
	s := NewSchemeResolver(map[string]Resolver{"file": &FileResolver{Root: "/"}})
	_, err := s.Resolve(context.Background(), "vault://cvap/ssh/cvapscan")
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("unknown scheme error = %v, want ErrUnsupportedScheme", err)
	}
}

func TestSchemeResolverDispatchesFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "k"), []byte("material"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr, _ := NewFileResolver(root)
	s := NewSchemeResolver(map[string]Resolver{"file": fr})
	got, err := s.Resolve(context.Background(), "file://"+filepath.Join(root, "k"))
	if err != nil || string(got) != "material" {
		t.Fatalf("dispatch = (%q, %v), want (material, nil)", got, err)
	}
}
