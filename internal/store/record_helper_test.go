package store_test

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// recordKey is Record for callers that only need the error: the inserted
// flag matters to correlate (a value live on another asset), not to these
// fixtures.
func recordKey(ctx context.Context, c *store.Conn, assetID uuid.UUID, k domain.IdentityKey, at time.Time,
	provenance store.KeyProvenance, scanID uuid.UUID, address string, port int) error {
	_, err := (store.AssetIdentityKeys{}).Record(ctx, c, assetID, k, at, provenance, scanID, address, port)
	return err
}
