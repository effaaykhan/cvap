// Package scanpoint is the Scan Point runtime: connection management, the lease
// client, the engine host and result buffering.
//
// It connects outbound only and never listens (ADR-005). It owns the send-path
// half of scope enforcement and the rate budget it allocates to engine
// processes (ADR-024, ADR-027), and it holds credentials so that engines never
// have to (ADR-020).
package scanpoint
