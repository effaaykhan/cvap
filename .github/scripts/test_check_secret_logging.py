#!/usr/bin/env python3
"""Test suite for check_secret_logging.py.

A gate that cannot fail is worse than no gate, because the first gets trusted.
This feeds the checker synthetic Go files covering the leaks it exists to catch
and the ordinary code it must not flag, and asserts both directions.

The negative cases matter as much as the positive ones. An over-strict check
that flags every slog call near a protobuf gets disabled by the first person it
inconveniences, which removes the protection for the two fields that need it.

Run: python3 .github/scripts/test_check_secret_logging.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("csl", HERE / "check_secret_logging.py")
csl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csl)

FLAG, CLEAN = "FLAG", "CLEAN"

CASES: list[tuple[str, str, str]] = [
    (
        "enrollment request into slog.Any",
        '''package enroll
func h(req *scanpointv1.EnrollRequest) {
    slog.Any("request", req)
}''',
        FLAG,
    ),
    (
        "credential grant formatted into an error",
        '''package dispatch
func send(grant *scanpointv1.CredentialGrant) error {
    return fmt.Errorf("grant failed: %v", grant)
}''',
        FLAG,
    ),
    (
        "String() called on a secret-bearing message",
        '''package dispatch
func trace(grant *scanpointv1.CredentialGrant) {
    println(grant.String())
}''',
        FLAG,
    ),
    (
        "the accessor alone, regardless of surrounding type",
        '''package scanpoint
func oops(g any) {
    slog.Info("material", "v", g.GetMaterial())
}''',
        FLAG,
    ),
    (
        "field access rather than accessor",
        '''package scanpoint
func oops(req *scanpointv1.EnrollRequest) {
    log.Printf("token=%s", req.EnrollmentToken)
}''',
        FLAG,
    ),
    (
        "CoreMessage is secret-bearing transitively through its oneof",
        '''package dispatch
func relay(msg *scanpointv1.CoreMessage) {
    slog.Debug("core message", "msg", msg)
}''',
        FLAG,
    ),
    (
        "declared with var rather than a parameter",
        '''package dispatch
func build() {
    var grant *scanpointv1.CredentialGrant
    fmt.Println(grant)
}''',
        FLAG,
    ),
    (
        "a composite literal bound to a name",
        '''package dispatch
func build() {
    g := &scanpointv1.CredentialGrant{GrantId: "x"}
    slog.Info("built", "g", g)
}''',
        FLAG,
    ),
    (
        "an accessor that RETURNS a secret-bearing message",
        '''package dispatch
func relay(msg *scanpointv1.CoreMessage) {
    slog.Info("dispatching", "credential", msg.GetCredential())
}''',
        FLAG,
    ),
    (
        # Bindings are per top-level function. This is the case that fired on
        # internal/protocol/compat_test.go, where `received` is a CoreMessage in
        # one test and a SubmitAck in another; a file-wide binding flagged the
        # SubmitAck line, which leaks nothing. Both directions are asserted so
        # neither half can rot -- narrowing the scope must not stop catching the
        # function that really does hold the secret.
        "a name reused in another function for a message that holds no secret",
        '''package protocol
func relay(msg *scanpointv1.CoreMessage) {
	_ = msg.GetMsg()
}

func roundTrip() {
	var received scanpointv1.SubmitAck
	fmt.Printf("ack: %v", &received)
}''',
        CLEAN,
    ),
    (
        "the same name in the function that does hold the secret is still caught",
        '''package protocol
func roundTrip() {
	var received scanpointv1.SubmitAck
	_ = received
}

func relay() {
	var received scanpointv1.CoreMessage
	fmt.Printf("core: %v", &received)
}''',
        FLAG,
    ),
    (
        "a package-level secret is visible inside every function",
        '''package dispatch

var pending *scanpointv1.CredentialGrant

func flush() {
	slog.Info("flushing", "g", pending)
}''',
        FLAG,
    ),
    (
        "logging a message that holds no secret",
        '''package ingest
func h(chunk *scanpointv1.ResultChunk) {
    slog.Info("chunk", "index", chunk.GetChunkIndex())
}''',
        CLEAN,
    ),
    (
        "logging a safe field of a secret-bearing message",
        '''package dispatch
func h(grant *scanpointv1.CredentialGrant) {
    slog.Info("grant issued", "grant_id", grant.GetGrantId())
}''',
        CLEAN,
    ),
    (
        "handling a secret without logging it",
        '''package scanpoint
func use(grant *scanpointv1.CredentialGrant) {
    session := establish(grant.GetMaterial())
    defer session.Close()
}''',
        CLEAN,
    ),
    (
        "a comment mentioning the accessor",
        '''package scanpoint
// Never pass grant.GetMaterial() to slog.Info(); see ADR-020.
func safe() {}''',
        CLEAN,
    ),
    (
        "ordinary logging with no protobuf at all",
        '''package control
func h(id string) {
    slog.Info("scan started", "scan_id", id)
}''',
        CLEAN,
    ),
]


def run_case(source: str) -> list[str]:
    """Run only the source-scanning half against one synthetic file."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "pkg").mkdir()
        (root / "pkg" / "x.go").write_text(source)
        original = csl.ROOT
        csl.ROOT = root
        try:
            return csl.check_sources()
        finally:
            csl.ROOT = original


def main() -> int:
    width = max(len(name) for name, _, _ in CASES)
    failures = 0

    print(f"{'#':>3}  {'case'.ljust(width)}  {'want':<6}  {'got':<6}  result")
    print("-" * (width + 32))

    for i, (name, source, want) in enumerate(CASES, 1):
        problems = run_case(source)
        got = FLAG if problems else CLEAN
        ok = got == want
        failures += not ok
        print(f"{i:>3}  {name.ljust(width)}  {want:<6}  {got:<6}  {'PASS' if ok else 'FAIL'}")
        if not ok and problems:
            for p in problems:
                print(f"       {p}")

    print("-" * (width + 32))
    print(f"{len(CASES) - failures}/{len(CASES)} passed")

    # The marker cross-check runs against the real contract, not a fixture.
    marker_problems = csl.check_markers()
    if marker_problems:
        print("\nmarker cross-check against the contract:")
        for p in marker_problems:
            print(f"  {p}")
        failures += len(marker_problems)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
