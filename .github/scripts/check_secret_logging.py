#!/usr/bin/env python3
"""Fail the build if a secret-bearing protobuf type reaches a logging call.

WHY THIS IS A GATE AND NOT A COMMENT
------------------------------------
internal/logging redacts on the attribute *key*, and its own doc says no type
holding credential material may implement String or MarshalJSON. Every generated
type under gen/ implements String() -- protoc-gen-go emits it unconditionally --
and it renders every field, including the enrollment token and credential
material. So the redactor cannot see these leaks:

    slog.Any("request", req)          key is "request"; token printed in full
    fmt.Errorf("enroll: %v", req)     token into an error, then a log or a
                                      gRPC status returned to the caller

Marking the fields [debug_redact = true] does not fix it either. The option is
defined in descriptorpb but protobuf-go consults it nowhere in its encoding
path -- verified by grep across the module, most recently at v1.36.11 -- so
String() still prints the secret. The marker is machine-readable intent; this script is what gives it
teeth, and logging.Proto() is what gives callers a safe alternative.

An enrollment token is a bearer credential that yields a full fleet identity.
Credential material is the customer's estate. Both sit in plain fields on
messages that an implementer debugging a stream will reach for first. Left as a
comment, this is violated in week 6 and nobody notices.

LIMITS, STATED HONESTLY
-----------------------
This is a lexical check over Go source, not type inference. It resolves
identifiers bound to secret types by declaration, parameter and composite
literal, which covers how these messages are actually handled. It will not catch
a secret reaching a log through an interface, a generic helper, or a variable
whose type comes from an unannotated multi-return assignment.

Bindings are resolved per top-level function, plus package scope, rather than
per file. Go code reuses short names -- msg, req, grant, received -- across
functions in a file, and a file-wide binding makes one function that handles a
CredentialGrant flag every unrelated `grant` in the file. That is the false
positive that gets a gate switched off, and it is not hypothetical: it fired on
internal/protocol/compat_test.go, where `received` is a CoreMessage in one test
and a SubmitAck in another.

Rule 3 compensates: any accessor for a secret field appearing anywhere inside a
formatting call is flagged regardless of what the surrounding types are. That
rule is sound, and it is the one that catches the direct leak.

The remaining gap is a gRPC payload-logging interceptor, which sees the messages
reflectively and defeats any source-level check. That is forbidden on Enrollment
and Dispatch by contract comment, and it is the one thing here a human review
still has to hold.

Run: python3 .github/scripts/check_secret_logging.py
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTO_DIR = ROOT / "proto" / "cybersentinel" / "scanpoint" / "v1"
GENERATED_PKG = "scanpointv1"

# The authoritative list. A field is here because leaking it is a compromise,
# not because it is merely sensitive. Adding a secret field to the contract
# means adding it here and marking it in the .proto; the script fails if the
# two disagree in either direction, so neither can drift from the other.
SECRET_FIELDS: dict[str, set[str]] = {
    "EnrollRequest": {"enrollment_token"},
    "CredentialGrant": {"material"},
}

# Calls that render their arguments somewhere a human or a file will see.
LOGGING_CALL = re.compile(
    r"\b(?:"
    r"slog\.(?:Any|Info|Debug|Warn|Error|Log|InfoContext|DebugContext|WarnContext|ErrorContext|Group|String)"
    r"|log\.(?:Print|Printf|Println|Fatal|Fatalf|Panic|Panicf)"
    r"|fmt\.(?:Print|Printf|Println|Sprint|Sprintf|Sprintln|Errorf|Fprint|Fprintf|Fprintln)"
    r"|(?:t|b)\.(?:Log|Logf|Error|Errorf|Fatal|Fatalf)"
    r")\s*\("
)

VERB = re.compile(r"%[-+ #0-9.]*[vqsdxX]")


def go_ident(name: str) -> str:
    """proto field_name -> generated Go accessor and field."""
    parts = name.split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts)


def secret_types() -> tuple[set[str], set[str]]:
    """Messages holding a secret field, those containing one, and the accessors
    that return one."""
    direct = set(SECRET_FIELDS)
    containing = set(direct)

    text = "\n".join(p.read_text() for p in sorted(PROTO_DIR.glob("*.proto")))
    blocks = dict(re.findall(r"\nmessage\s+(\w+)\s*\{(.*?)\n\}", text, re.S))

    changed = True
    while changed:
        changed = False
        for name, body in blocks.items():
            if name in containing:
                continue
            for held in containing:
                if re.search(rf"(?:^|\s){re.escape(held)}\s+\w+\s*=\s*\d+", body, re.M):
                    containing.add(name)
                    changed = True
                    break

    # Accessors that RETURN a secret-bearing message. CoreMessage.credential is
    # the live case: msg.GetCredential() hands a CredentialGrant straight to a
    # formatter without the identifier itself ever appearing bare.
    returning: set[str] = set()
    for _name, body in blocks.items():
        for held in containing:
            for fname in re.findall(rf"(?:^|\s){re.escape(held)}\s+(\w+)\s*=\s*\d+", body, re.M):
                returning.add(f"Get{go_ident(fname)}()")

    return direct, containing, returning


def check_markers() -> list[str]:
    """The .proto markers and SECRET_FIELDS must agree, both directions."""
    problems: list[str] = []
    text = "\n".join(p.read_text() for p in sorted(PROTO_DIR.glob("*.proto")))
    blocks = dict(re.findall(r"\nmessage\s+(\w+)\s*\{(.*?)\n\}", text, re.S))

    marked: dict[str, set[str]] = {}
    for name, body in blocks.items():
        for fname in re.findall(r"\s(\w+)\s*=\s*\d+\s*\[[^\]]*debug_redact\s*=\s*true[^\]]*\]", body):
            marked.setdefault(name, set()).add(fname)

    for message, fields in SECRET_FIELDS.items():
        if message not in blocks:
            problems.append(f"SECRET_FIELDS names {message}, which is not in the contract")
            continue
        for field in fields:
            if field not in marked.get(message, set()):
                problems.append(
                    f"{message}.{field} is listed as secret but is not marked "
                    f"[debug_redact = true] in the contract"
                )
    for message, fields in marked.items():
        for field in fields:
            if field not in SECRET_FIELDS.get(message, set()):
                problems.append(
                    f"{message}.{field} is marked [debug_redact = true] but is not in "
                    f"SECRET_FIELDS in {pathlib.Path(__file__).name}"
                )
    return problems


def scopes(source: str) -> tuple[str, list[tuple[str, list[tuple[int, str]]]]]:
    """Split Go source into package scope and one region per top-level func.

    Relies on gofmt, which CI enforces: a top-level declaration starts in
    column 0 and a top-level func body ends at a line that is exactly "}".
    A file that is not gofmt-clean degrades toward the old file-wide
    behaviour, which is the safe direction -- more flagged, not fewer.
    """
    lines = source.split("\n")
    package: list[tuple[int, str]] = []
    funcs: list[tuple[str, list[tuple[int, str]]]] = []

    i, n = 0, len(lines)
    while i < n:
        if lines[i].startswith("func "):
            body: list[tuple[int, str]] = []
            while i < n:
                body.append((i + 1, lines[i]))
                closed = lines[i] == "}"
                i += 1
                if closed:
                    break
            funcs.append(("\n".join(l for _, l in body), body))
        else:
            package.append((i + 1, lines[i]))
            i += 1

    return "\n".join(l for _, l in package), [("", package)] + funcs


def bound_identifiers(source: str, types: set[str]) -> set[str]:
    """Identifiers whose declared type is one of the secret-bearing messages."""
    idents: set[str] = set()
    alt = "|".join(sorted(re.escape(t) for t in types))
    pat = rf"\*?(?:{GENERATED_PKG}\.)?(?:{alt})\b"
    for m in re.finditer(rf"\bvar\s+(\w+)\s+{pat}", source):
        idents.add(m.group(1))
    for m in re.finditer(rf"\b(\w+)\s*:?=\s*&?(?:{GENERATED_PKG}\.)?(?:{alt})\s*\{{", source):
        idents.add(m.group(1))
    for m in re.finditer(rf"\(\s*(?:\w+\s+[^)]*?)?\b(\w+)\s+{pat}", source):
        idents.add(m.group(1))
    for m in re.finditer(rf"\b(\w+)\s+{pat}\s*[,)]", source):
        idents.add(m.group(1))
    return {i for i in idents if i not in {"_", "err", "ctx"}}


STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`')


def call_arguments(line: str) -> str:
    m = LOGGING_CALL.search(line)
    return line[m.end():] if m else ""


def without_strings(text: str) -> str:
    """Blank out string literals before matching identifiers.

    slog calls name their attributes, so a log of grant.GetGrantId() reads
    slog.Info("grant issued", "grant_id", ...). Matching identifiers against the
    raw line finds `grant` inside those labels and flags a call that leaks
    nothing -- the false positive that gets a gate switched off.
    """
    return STRING_LITERAL.sub(lambda m: " " * len(m.group(0)), text)


def check_sources() -> list[str]:
    _direct, containing, returning = secret_types()
    accessors = {
        f"Get{go_ident(f)}()" for fields in SECRET_FIELDS.values() for f in fields
    } | {f".{go_ident(f)}" for fields in SECRET_FIELDS.values() for f in fields} | returning

    problems: list[str] = []
    for path in sorted(ROOT.rglob("*.go")):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in {"gen", ".git"}:
            continue
        source = path.read_text()
        package_text, regions = scopes(source)
        package_idents = bound_identifiers(package_text, containing)

        for region_text, region_lines in regions:
            # A package-level var is visible inside every function, so it is
            # carried into each region. A local is not, which is the point.
            idents = package_idents | bound_identifiers(region_text, containing)

            for n, line in region_lines:
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue

                args = call_arguments(line)
                if args:
                    # Rule 3: a secret accessor inside a formatting call. Sound.
                    for accessor in accessors:
                        if accessor in args:
                            problems.append(
                                f"{rel}:{n}: secret field accessor {accessor} passed to a logging "
                                f"call. Strip it, or use logging.Proto()."
                            )
                    # Rule 2: a secret-bearing message passed to a formatting call.
                    bare = without_strings(args)
                    for ident in idents:
                        # Bare use only. `grant` is the secret; `grant.GetGrantId()`
                        # is not, and flagging it would make the gate the kind of
                        # nuisance that gets switched off.
                        if re.search(rf"\b{re.escape(ident)}\b(?!\s*\.)", bare):
                            problems.append(
                                f"{rel}:{n}: {ident} is a secret-bearing protobuf message passed "
                                f"to a logging call; its String() renders every field. "
                                f"Use logging.Proto()."
                            )
                    if VERB.search(line):
                        for t in sorted(containing):
                            if re.search(rf"\b{GENERATED_PKG}\.{t}\b", bare):
                                problems.append(
                                    f"{rel}:{n}: {GENERATED_PKG}.{t} formatted into a log or error "
                                    f"string. Use logging.Proto()."
                                )

                # Rule 1: String() on a secret-bearing message, anywhere.
                for ident in idents:
                    if re.search(rf"\b{re.escape(ident)}\.String\s*\(\s*\)", line):
                        problems.append(
                            f"{rel}:{n}: {ident}.String() renders credential material. "
                            f"Use logging.Proto()."
                        )

    # Regions are visited package-scope-first, so a file's problems can come
    # back out of line order. Sort before reporting: a gate whose output order
    # wanders between runs is one nobody can diff.
    return sorted(problems, key=_location)


def _location(problem: str) -> tuple[str, int]:
    """Sort key: the "path:line:" prefix every problem message carries."""
    path, _, rest = problem.partition(":")
    line, _, _ = rest.partition(":")
    return path, int(line) if line.isdigit() else 0


def main() -> int:
    problems = check_markers() + check_sources()

    if not SECRET_FIELDS:
        print("SECRET_FIELDS is empty -- this gate would pass vacuously.", file=sys.stderr)
        return 1

    if problems:
        print("Secret-bearing protobuf types must never reach a logging call.\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            f"\n{len(problems)} problem(s). See .github/scripts/check_secret_logging.py "
            f"for what this checks and what it cannot.",
            file=sys.stderr,
        )
        return 1

    watched = ", ".join(f"{m}.{f}" for m, fs in SECRET_FIELDS.items() for f in sorted(fs))
    print(f"Secret logging check OK: {watched} not reachable from any logging call.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
