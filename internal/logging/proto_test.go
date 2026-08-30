package logging_test

import (
	"bytes"
	"log/slog"
	"testing"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/logging"
)

// newBareLogger returns a logger with no ReplaceAttr pass.
//
// Deliberately not logging.New: with the key-based redactor in place, a
// redacted "material" could have come from either control, and these tests are
// about the one inside Proto. Everywhere outside this file, construct loggers
// through logging.New.
func newBareLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

// group descends one level into the decoded JSON, failing rather than panicking
// on the wrong shape.
func group(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("no %q in %v", key, m)
	}
	g, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%q is %T, want an object", key, v)
	}
	return g
}

func TestProtoRedactsCredentialMaterial(t *testing.T) {
	grant := &scanpointv1.CredentialGrant{
		GrantId:     "grant-1",
		JobId:       "job-1",
		ExpiresUnix: 1756500000,
		Material:    []byte("hunter2"),
		Scope:       []string{"10.0.0.1", "10.0.0.2"},
		CredKind:    scanpointv1.CredKind_SESSION_HANDLE,
	}

	bare, buf := newBareLogger()
	bare.Info("grant issued", logging.ProtoAttr("grant", grant))
	out := group(t, decode(t, buf), "grant")

	if out["material"] != logging.Placeholder {
		t.Errorf("material = %v, want %q", out["material"], logging.Placeholder)
	}
	if out["grant_id"] != "grant-1" {
		t.Errorf("grant_id = %v, want grant-1; redacting the whole message would "+
			"make Proto useless and get callers reaching for %%v again", out["grant_id"])
	}
	if out["cred_kind"] != "SESSION_HANDLE" {
		t.Errorf("cred_kind = %v, want the enum value name SESSION_HANDLE", out["cred_kind"])
	}
	if scope := group(t, out, "scope"); scope["0"] != "10.0.0.1" || scope["1"] != "10.0.0.2" {
		t.Errorf("scope = %v, want both targets in order", scope)
	}
}

func TestProtoRendersBytesAsLengthNotContent(t *testing.T) {
	req := &scanpointv1.EnrollRequest{
		EnrollmentToken: "tok-abcdef",
		Csr:             []byte("012345678"),
		Hostname:        "sp-lab-1",
	}

	bare, buf := newBareLogger()
	bare.Info("enrolling", logging.ProtoAttr("request", req))
	out := group(t, decode(t, buf), "request")

	if out["enrollment_token"] != logging.Placeholder {
		t.Errorf("enrollment_token = %v, want %q", out["enrollment_token"], logging.Placeholder)
	}
	if out["csr"] != "9 bytes" {
		t.Errorf("csr = %v, want a length; a CSR, a certificate and an evidence "+
			"payload are all bytes on this contract", out["csr"])
	}
	if out["hostname"] != "sp-lab-1" {
		t.Errorf("hostname = %v, want sp-lab-1", out["hostname"])
	}
}

// The case the gate exists for: the secret is two levels down, inside a oneof,
// and String() on the outer message renders it in full.
//
// It also pins the boundary of the name heuristic. "credential" is a
// credential-shaped name, but the field is a message, so Proto descends into it
// rather than collapsing it: material is withheld by its marker, and the audit
// fields around it stay readable. Redacting on the name here would hide
// grant_id and job_id, which is what a caller is reading the line for.
func TestProtoRedactsThroughNesting(t *testing.T) {
	msg := &scanpointv1.CoreMessage{
		Msg: &scanpointv1.CoreMessage_Credential{
			Credential: &scanpointv1.CredentialGrant{
				GrantId:  "grant-2",
				Material: []byte("hunter2"),
			},
		},
	}

	bare, buf := newBareLogger()
	bare.Info("dispatching", logging.ProtoAttr("core", msg))
	inner := group(t, group(t, decode(t, buf), "core"), "credential")

	if inner["material"] != logging.Placeholder {
		t.Errorf("nested material = %v, want %q", inner["material"], logging.Placeholder)
	}
	if inner["grant_id"] != "grant-2" {
		t.Errorf("nested grant_id = %v, want grant-2", inner["grant_id"])
	}
	if line := buf.String(); bytes.Contains([]byte(line), []byte("hunter2")) {
		t.Errorf("the secret reached the output: %s", line)
	}
}

func TestProtoOnNilMessage(t *testing.T) {
	var grant *scanpointv1.CredentialGrant

	bare, buf := newBareLogger()
	bare.Info("no grant", logging.ProtoAttr("grant", grant))
	out := decode(t, buf)

	if out["grant"] != "<nil>" {
		t.Errorf("grant = %v, want <nil>; a typed nil must not panic the logger", out["grant"])
	}
}
