package dispatch

import (
	"context"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/store"
)

// OfferWorkForTest runs one assignment pass for a scan point without a stream,
// so a test can hand offerWork an outbound channel it controls — full, or
// unbuffered with no reader — and observe what the grant path does when the
// send is refused. The session it builds is the one Connect would build after
// the handshake, minus the stream.
func (s *Service) OfferWorkForTest(ctx context.Context, tenant store.TenantID, spID uuid.UUID, fingerprint string,
	out chan<- *scanpointv1.CoreMessage, limit int,
) {
	s.offerWork(ctx, &session{tenant: tenant, spID: spID, fingerprint: fingerprint}, out, limit)
}
