package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/logging"
)

func newTestLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logging.New(&buf, logging.Options{Level: slog.LevelDebug}), &buf
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	var out map[string]any
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("output is not JSON: %v\nline: %s", err, line)
	}
	return out
}

func TestRedactsCredentialShapedKeys(t *testing.T) {
	keys := []string{
		"password", "Password", "passwd", "passphrase",
		"secret", "client_secret", "api_key", "apiKey", "API-KEY",
		"token", "access_token", "bearer",
		"credential", "credential_material", "material",
		"private_key", "signing_key", "access_key", "authorization",
	}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			log, buf := newTestLogger(t)
			log.Info("test", slog.String(k, "hunter2"))
			if got := decode(t, buf)[k]; got != logging.Placeholder {
				t.Errorf("key %q: value reached the sink: got %v", k, got)
			}
			if strings.Contains(buf.String(), "hunter2") {
				t.Errorf("key %q: secret present in raw output: %s", k, buf.String())
			}
		})
	}
}

func TestPreservesKeysThatOnlyLookSensitive(t *testing.T) {
	// These are load-bearing identifiers in this system. Redacting them would
	// make the logs useless and get the redactor weakened.
	keys := []string{"dedup_key", "identity_key", "host_key", "key_type", "signature_digest", "cred_kind"}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			log, buf := newTestLogger(t)
			log.Info("test", slog.String(k, "visible"))
			if got := decode(t, buf)[k]; got != "visible" {
				t.Errorf("key %q was redacted but should not be: got %v", k, got)
			}
		})
	}
}

func TestRedactsInsideGroups(t *testing.T) {
	log, buf := newTestLogger(t)
	log.Info("test", slog.Group("grant", slog.String("grant_id", "g-1"), slog.String("material", "hunter2")))

	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("secret escaped through a group: %s", buf.String())
	}
	grant, ok := decode(t, buf)["grant"].(map[string]any)
	if !ok {
		t.Fatalf("group missing from output: %s", buf.String())
	}
	if grant["material"] != logging.Placeholder {
		t.Errorf("nested material not redacted: %v", grant["material"])
	}
	if grant["grant_id"] != "g-1" {
		t.Errorf("non-sensitive sibling was altered: %v", grant["grant_id"])
	}
}

func TestRedactsAttrsBoundWithWith(t *testing.T) {
	log, buf := newTestLogger(t)
	log.With(slog.String("api_key", "hunter2")).Info("test")
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("secret escaped through With: %s", buf.String())
	}
}

func TestIsSensitiveKey(t *testing.T) {
	if !logging.IsSensitiveKey("SSH_Private_Key") {
		t.Error("expected SSH_Private_Key to be sensitive")
	}
	if logging.IsSensitiveKey("asset_id") {
		t.Error("expected asset_id not to be sensitive")
	}
}
