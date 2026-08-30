// Package logging builds the process-wide structured logger.
//
// Output is JSON via log/slog, and every attribute passes through a redaction
// pass that replaces the value of any credential-shaped key before it reaches a
// sink. Credentials must never reach a log (ADR-020), and redaction added after
// the fact is how they get there.
package logging
