package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func caNotAfter(t *testing.T, dir string) time.Time {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("ca.crt is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c.NotAfter
}

// TestDevCAValidityIsConfigurable covers the flag added so an evaluation CA does
// not expire mid-review: the default is a short 24h, --valid-for extends it, and
// a value past the 90-day ceiling is refused so a "development" CA stays one.
func TestDevCAValidityIsConfigurable(t *testing.T) {
	log := discardLog()

	// Default: ~24h.
	def := t.TempDir()
	if err := devCA(log, []string{def}); err != nil {
		t.Fatalf("default dev-ca: %v", err)
	}
	if d := time.Until(caNotAfter(t, def)); d > 25*time.Hour || d < 23*time.Hour {
		t.Errorf("default validity ~24h, got %s", d)
	}

	// --valid-for 720h (30 days) for an evaluation.
	ext := t.TempDir()
	if err := devCA(log, []string{"--valid-for", "720h", ext}); err != nil {
		t.Fatalf("extended dev-ca: %v", err)
	}
	if d := time.Until(caNotAfter(t, ext)); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("--valid-for 720h should be ~30d, got %s", d)
	}

	// Past the 90-day ceiling: refused, and nothing written.
	over := t.TempDir()
	if err := devCA(log, []string{"--valid-for", "3000h", over}); err == nil {
		t.Error("a validity beyond the 90-day ceiling must be refused")
	}
	if _, err := os.Stat(filepath.Join(over, "ca.crt")); !os.IsNotExist(err) {
		t.Error("a refused dev-ca must not have written a certificate")
	}
}
