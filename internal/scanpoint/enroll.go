package scanpoint

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// Enroll exchanges the enrollment token for a certificate, once.
//
// ADR-018: the token is exchanged exactly ONCE. There is no re-enrolment path
// here — a scan point that has an identity rotates it (Rotate below), and one
// that has lost its key needs a new token from an operator. That asymmetry is
// deliberate: an automatic re-enrolment on a missing key would turn "somebody
// deleted the data directory" into "this scan point silently acquired a second
// identity", and the fingerprint is what the audit log attributes actions to.
//
// The key pair is generated HERE and the private half never leaves. That is what
// makes cert_fingerprint a per-device identity rather than a label, and it is
// what CREDENTIAL_GRANT.delivered_to_fingerprint and immediate per-device
// revocation both rest on (ADR-020).
func Enroll(ctx context.Context, log *slog.Logger, cfg Config, client scanpointv1.EnrollmentClient) (*Identity, error) {
	token, err := ReadToken(cfg.TokenPath)
	if err != nil {
		return nil, err
	}
	// Spent as soon as the call returns, whatever the outcome: a failed
	// enrolment does not make the token safe to keep in memory, and ADR-018
	// makes it single-use so a retry with the same value would be refused
	// anyway.
	defer token.Zeroise()

	engines, err := NewEngineSet(ctx, cfg.EngineBinaries)
	if err != nil {
		return nil, err
	}
	caps := engines.Capabilities()

	key, csr, err := NewKey()
	if err != nil {
		return nil, err
	}

	resp, err := client.Enroll(ctx, &scanpointv1.EnrollRequest{
		// Reveal() at the call site and nowhere else. The value is in the
		// request message for the duration of the RPC, which is the exposure
		// ADR-038 describes as best-effort and irreducible at this layer.
		EnrollmentToken: string(token.Reveal()),
		Csr:             csr,
		// Self-asserted, operator display only. It authenticates nothing,
		// selects no zone and no policy, and is not an asset identity key
		// (enrollment.proto).
		Hostname:        cfg.Hostname,
		AgentVersion:    cfg.AgentVersion,
		ProtocolVersion: cfg.ProtocolVersion,
		Capabilities:    caps,
	})
	if err != nil {
		return nil, fmt.Errorf("scanpoint: enrollment refused: %w", err)
	}

	id := identityFrom(resp)
	if err := SaveIdentity(cfg.DataDir, key, resp.GetCertificate(), resp.GetCaChain(), id); err != nil {
		return nil, err
	}
	log.Info("enrolled",
		slog.String("scan_point_id", id.ScanPointID),
		slog.String("fingerprint", id.Fingerprint),
		slog.Time("certificate_expires", id.NotAfter))
	return id, nil
}

// Rotate replaces the certificate before it expires.
//
// Authenticated by the certificate being REPLACED, over the mTLS connection
// itself — there is no token, because ADR-018 spends it once. RotateRequest
// carries no fingerprint either: field 3 was removed and reserved in ADR-028
// precisely because a non-secret, attacker-known value in a field shaped like an
// authentication input invites Core to check the body instead of the peer
// certificate.
//
// A new key pair each time, not a re-signing of the old one. Rotation whose only
// effect is a later expiry date leaves a key that has been on a scan point in a
// hostile network for its whole life.
func Rotate(ctx context.Context, log *slog.Logger, cfg Config, id *Identity, client scanpointv1.EnrollmentClient) (*Identity, error) {
	engines, err := NewEngineSet(ctx, cfg.EngineBinaries)
	if err != nil {
		return nil, err
	}
	caps := engines.Capabilities()
	key, csr, err := NewKey()
	if err != nil {
		return nil, err
	}

	resp, err := client.RotateCertificate(ctx, &scanpointv1.RotateRequest{
		ScanPointId:     id.ScanPointID,
		Csr:             csr,
		AgentVersion:    cfg.AgentVersion,
		ProtocolVersion: cfg.ProtocolVersion,
		// Re-declared because rotation is when an upgraded agent restates what
		// it can do: engines are replaced independently of the runtime, so the
		// capability set at rotation is routinely not the set at enrolment.
		Capabilities: caps,
	})
	if err != nil {
		return nil, fmt.Errorf("scanpoint: rotation refused: %w", err)
	}

	next := identityFrom(resp)
	if err := SaveIdentity(cfg.DataDir, key, resp.GetCertificate(), resp.GetCaChain(), next); err != nil {
		return nil, err
	}
	log.Info("certificate rotated",
		slog.String("fingerprint", next.Fingerprint),
		slog.Time("expires", next.NotAfter))
	return next, nil
}

// maxEndpoint bounds a value Core sends that this runtime persists and dials.
const maxEndpoint = 512

// safeField rejects anything that cannot be written to the identity file or
// handed to a dialler.
//
// The identity file is `key=value` lines parsed last-wins, so a newline in any
// value injects arbitrary keys — a dispatch endpoint containing "\ningest=evil"
// would redirect result submission on the next start. These values also become
// grpc.NewClient targets, where a "unix://" or "dns://" prefix selects a
// resolver. Core is the trusted issuer so none of this is exploitable today, and
// that is exactly the assumption worth not depending on: the check costs
// nothing and the failure it prevents is silent.
func safeField(v string) string {
	if len(v) > maxEndpoint {
		return ""
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return v
}

func identityFrom(resp *scanpointv1.EnrollResponse) *Identity {
	return &Identity{
		ScanPointID:     safeField(resp.GetScanPointId()),
		Fingerprint:     safeField(resp.GetCertFingerprint()),
		NotAfter:        time.Unix(resp.GetNotAfterUnix(), 0).UTC(),
		DispatchAddr:    safeField(resp.GetDispatchEndpoint()),
		IngestAddr:      safeField(resp.GetIngestEndpoint()),
		RulePacksAddr:   safeField(resp.GetRulepacksEndpoint()),
		AcceptedVersion: safeField(resp.GetAcceptedProtocolVersion()),
		MinVersion:      safeField(resp.GetMinSupportedVersion()),
	}
}
