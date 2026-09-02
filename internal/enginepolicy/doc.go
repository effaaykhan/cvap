// Package enginepolicy holds the import policy for scan engines.
//
// It contains no production code. It exists as a separate package for one
// reason: the guard must not be subject to itself. Living in internal/engines,
// the policy test's own imports — go/build, os, path/filepath — were checked
// against the allowlist it enforces, and it failed itself. Adding those to the
// engine allowlist to fix that would have been the wrong repair: `os` is on the
// list of things an engine must never import, because os.StartProcess spawns a
// subprocess without naming os/exec.
//
// It also widens the unit. ADR-027's deliverable is a separate PROCESS, so the
// eventual cmd/cvap-engine-* main that links an engine and speaks the job
// contract is as much "engine code" as the package it links — and it would sit
// outside internal/engines, unguarded, if the walk stopped there.
package enginepolicy
