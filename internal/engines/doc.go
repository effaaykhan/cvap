// Package engines holds the scan engines, one sub-package per engine, each
// running as a separate process behind the job contract (ADR-027).
//
// Engines receive resolved, pre-authorised targets and emit observations. They
// hold no scope data, no credentials and no database access, and they parse
// hostile input by design.
package engines
