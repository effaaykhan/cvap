package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The sighting window (ADR-091/094/096; ADR-100): how long a sighting counts
// toward the observed trust root, and how long an address is evidence of the
// same host. One value, read from identity_settings per tenant, so the trust
// root cannot outlive the address relationship it rests on — the two used to
// be equal constants in two packages, asserted equal by a test. Absent row =
// the default.
const (
	DefaultSightingWindow = 7 * 24 * time.Hour
	MinSightingWindow     = 24 * time.Hour
	MaxSightingWindow     = 90 * 24 * time.Hour
)

// ErrWindowOutOfBounds is a window outside [MinSightingWindow, MaxSightingWindow].
var ErrWindowOutOfBounds = errors.New("store: sighting window outside its bounds")

// IdentitySettings reads and writes a tenant's identity tuning.
type IdentitySettings struct{}

// Window returns the tenant's sighting window, or the default when none is set.
func (IdentitySettings) Window(ctx context.Context, c *Conn) (time.Duration, error) {
	var secs float64
	err := c.QueryRow(ctx, `SELECT extract(epoch FROM sighting_window) FROM identity_settings WHERE tenant_id = $1`,
		c.Tenant().UUID()).Scan(&secs)
	if err != nil {
		if errors.Is(mapError(err), ErrNotFound) {
			return DefaultSightingWindow, nil
		}
		return 0, mapError(err)
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// SetWindow writes the tenant's sighting window. Bounded here as well as in
// the schema, so the refusal names the bound rather than a CHECK constraint.
func (IdentitySettings) SetWindow(ctx context.Context, c *Conn, window time.Duration, by *uuid.UUID, at time.Time) error {
	if window < MinSightingWindow || window > MaxSightingWindow {
		return fmt.Errorf("%w: %s is not within [%s, %s]", ErrWindowOutOfBounds, window, MinSightingWindow, MaxSightingWindow)
	}
	const q = `
		INSERT INTO identity_settings (tenant_id, sighting_window, updated_at, updated_by)
		VALUES ($1, make_interval(secs => $2), $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET sighting_window = EXCLUDED.sighting_window,
		    updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), window.Seconds(), at, by)
	return mapError(err)
}

// IsDefault reports whether no operator has set the window for this tenant.
func (IdentitySettings) IsDefault(ctx context.Context, c *Conn) (bool, error) {
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM identity_settings WHERE tenant_id = $1`, c.Tenant().UUID()).Scan(&n); err != nil {
		return false, mapError(err)
	}
	return n == 0, nil
}
