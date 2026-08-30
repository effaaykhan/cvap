// Package dispatch holds the job broker, the Dispatch service and the Ingest
// service.
//
// The broker is internal to Core and is never reachable from a Scan Point
// (ADR-004): Scan Points hold an outbound stream to Dispatch, which pulls on
// their behalf. Ingest is a separate service so that a long result upload
// cannot head-of-line block job assignment (ADR-005, ADR-026).
package dispatch
