// Package domain holds the pure model: Observation, Asset, Finding and their
// relatives, together with identity resolution.
//
// No I/O of any kind belongs here — no database, no network, no filesystem, no
// unmediated clock. Identity resolution is a pure function of observations so
// that it can be re-run over history without re-scanning (ADR-006, ADR-007).
package domain
