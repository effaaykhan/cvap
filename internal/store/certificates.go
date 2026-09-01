package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SupersedeReason mirrors certificate_supersede_reason.
type SupersedeReason string

const (
	SupersedeRotation     SupersedeReason = "rotation"
	SupersedeRevocation   SupersedeReason = "revocation"
	SupersedeReenrollment SupersedeReason = "reenrollment"
	SupersedeExpiry       SupersedeReason = "expiry"
)

// Certificate is one issued scan point certificate, live or superseded.
type Certificate struct {
	ID              uuid.UUID
	ScanPointID     uuid.UUID
	Fingerprint     string
	SerialNumber    string
	NotBefore       time.Time
	NotAfter        time.Time
	IssuedAt        time.Time
	SupersededAt    *time.Time
	SupersedeReason *SupersedeReason
}

// NewScanPoint is what EnrollScanPoint needs to create one.
type NewScanPoint struct {
	ScanPointID     uuid.UUID
	ZoneID          uuid.UUID
	Hostname        string
	AgentVersion    string
	ProtocolVersion string

	Fingerprint  string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
}

type Certificates struct{}

// ============================================================================
// The pairing invariant, and the one statement that holds it.
// ============================================================================
//
// scan_points.cert_fingerprint must always name the live row in
// scan_point_certificates for that scan point. The two answer different
// questions — "who is this peer now", one indexed equality on the authentication
// path, versus "which certificate was valid on 3 March" — and both are needed.
//
// There is no constraint enforcing the agreement. Doing so needs a circular
// foreign key with DEFERRABLE INITIALLY DEFERRED on one side, and a deferred
// constraint is the kind of cleverness that surprises whoever debugs it at 2am.
//
// So the two writes are ONE STATEMENT instead. In EnrollScanPoint the
// certificate row takes its fingerprint FROM the scan point row being inserted;
// in RotateCertificate the scan point row takes its fingerprint FROM the
// certificate row being inserted. Either way there is no window where one exists
// without the other, and no way for a caller to perform half of it.
//
// ANY code path that writes scan_points.cert_fingerprint outside these two
// statements is a defect. internal/store/CLAUDE.md says so too, because that is
// where someone will look before writing the third one.

// EnrollScanPoint creates a scan point and its first certificate in one
// statement.
//
// The certificate row's fingerprint is selected from the scan point row rather
// than passed twice, so the two cannot disagree even if a future caller passes
// something inconsistent — there is only one value.
func (Certificates) EnrollScanPoint(ctx context.Context, c *Conn, sp NewScanPoint) (*Certificate, error) {
	const q = `
		WITH point AS (
		    INSERT INTO scan_points
		        (scan_point_id, tenant_id, zone_id, hostname,
		         agent_version, protocol_version, cert_fingerprint)
		    VALUES ($1, $2, $3, $4, $5, $6, $7)
		    RETURNING scan_point_id, tenant_id, cert_fingerprint
		)
		INSERT INTO scan_point_certificates
		    (tenant_id, scan_point_id, cert_fingerprint, serial_number,
		     not_before, not_after)
		SELECT point.tenant_id, point.scan_point_id, point.cert_fingerprint,
		       $8, $9, $10
		  FROM point
		RETURNING certificate_id, scan_point_id, cert_fingerprint, serial_number,
		          not_before, not_after, issued_at, superseded_at, supersede_reason`

	var cert Certificate
	err := c.QueryRow(ctx, q,
		sp.ScanPointID, c.Tenant().UUID(), sp.ZoneID, sp.Hostname,
		sp.AgentVersion, sp.ProtocolVersion, sp.Fingerprint,
		sp.SerialNumber, sp.NotBefore, sp.NotAfter,
	).Scan(&cert.ID, &cert.ScanPointID, &cert.Fingerprint, &cert.SerialNumber,
		&cert.NotBefore, &cert.NotAfter, &cert.IssuedAt,
		&cert.SupersededAt, &cert.SupersedeReason)
	if err != nil {
		return nil, mapError(err)
	}
	return &cert, nil
}

// Supersede marks a scan point's live certificate as no longer current.
//
// Separate from the pairing statement below, and that is deliberate rather than
// sloppy: the partial unique index permits one live row per scan point, so the
// old row must leave the index before the new one enters it. Both run inside the
// caller's transaction, so no other session observes the gap — and the pairing
// statement, which is the invariant that matters, stays indivisible.
//
// Returns the superseded fingerprint, for the audit record.
func (Certificates) Supersede(ctx context.Context, c *Conn, scanPointID uuid.UUID, reason SupersedeReason) (string, error) {
	const q = `
		UPDATE scan_point_certificates
		   SET superseded_at = now(), supersede_reason = $3
		 WHERE tenant_id = $1 AND scan_point_id = $2 AND superseded_at IS NULL
		RETURNING cert_fingerprint`

	var fingerprint string
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanPointID, string(reason)).Scan(&fingerprint)
	if err != nil {
		return "", mapError(err)
	}
	return fingerprint, nil
}

// RotateCertificate issues a new certificate and repoints the scan point at it,
// in one statement.
//
// scan_points.cert_fingerprint is set FROM the row just inserted, so the two
// cannot diverge. The old certificate stops authenticating at COMMIT: the
// fingerprint it carries is no longer the one scan_points holds, so
// tenant_for_scan_point resolves it to nothing. That is the whole of revocation
// — no CRL, no OCSP, and immediate (ADR-018).
//
// Call Supersede first, in the same transaction.
func (Certificates) RotateCertificate(ctx context.Context, c *Conn, scanPointID uuid.UUID, fingerprint, serial string, notBefore, notAfter time.Time) (*Certificate, error) {
	const q = `
		WITH issued AS (
		    INSERT INTO scan_point_certificates
		        (tenant_id, scan_point_id, cert_fingerprint, serial_number,
		         not_before, not_after)
		    VALUES ($1, $2, $3, $4, $5, $6)
		    RETURNING certificate_id, tenant_id, scan_point_id, cert_fingerprint,
		              serial_number, not_before, not_after, issued_at
		), repointed AS (
		    UPDATE scan_points sp
		       SET cert_fingerprint = issued.cert_fingerprint
		      FROM issued
		     WHERE sp.tenant_id = issued.tenant_id
		       AND sp.scan_point_id = issued.scan_point_id
		    RETURNING sp.scan_point_id
		)
		SELECT issued.certificate_id, issued.scan_point_id, issued.cert_fingerprint,
		       issued.serial_number, issued.not_before, issued.not_after, issued.issued_at
		  FROM issued
		  JOIN repointed ON repointed.scan_point_id = issued.scan_point_id`

	var cert Certificate
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanPointID, fingerprint, serial, notBefore, notAfter).
		Scan(&cert.ID, &cert.ScanPointID, &cert.Fingerprint, &cert.SerialNumber,
			&cert.NotBefore, &cert.NotAfter, &cert.IssuedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &cert, nil
}

// Live returns the current certificate for a scan point.
func (Certificates) Live(ctx context.Context, c *Conn, scanPointID uuid.UUID) (*Certificate, error) {
	const q = `
		SELECT certificate_id, scan_point_id, cert_fingerprint, serial_number,
		       not_before, not_after, issued_at, superseded_at, supersede_reason
		  FROM scan_point_certificates
		 WHERE tenant_id = $1 AND scan_point_id = $2 AND superseded_at IS NULL`

	var cert Certificate
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanPointID).
		Scan(&cert.ID, &cert.ScanPointID, &cert.Fingerprint, &cert.SerialNumber,
			&cert.NotBefore, &cert.NotAfter, &cert.IssuedAt,
			&cert.SupersededAt, &cert.SupersedeReason)
	if err != nil {
		return nil, mapError(err)
	}
	return &cert, nil
}

// History returns every certificate issued to a scan point, newest first. The
// question this table exists to answer.
func (Certificates) History(ctx context.Context, c *Conn, scanPointID uuid.UUID) ([]Certificate, error) {
	const q = `
		SELECT certificate_id, scan_point_id, cert_fingerprint, serial_number,
		       not_before, not_after, issued_at, superseded_at, supersede_reason
		  FROM scan_point_certificates
		 WHERE tenant_id = $1 AND scan_point_id = $2
		 ORDER BY issued_at DESC`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanPointID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		var cert Certificate
		if err := rows.Scan(&cert.ID, &cert.ScanPointID, &cert.Fingerprint, &cert.SerialNumber,
			&cert.NotBefore, &cert.NotAfter, &cert.IssuedAt,
			&cert.SupersededAt, &cert.SupersedeReason); err != nil {
			return nil, mapError(err)
		}
		out = append(out, cert)
	}
	return out, mapError(rows.Err())
}
