#!/usr/bin/env python3
"""
CVAP PreToolUse guard.

Blocks Bash commands that would point a scanning tool at an address outside the
lab scope. During development the scanner is repeatedly run to test it, and an
accidental run against a real network is a legal problem, not a bug.

Allowlist comes from lab/scope.txt (one CIDR or IP per line, # for comments).
Falls back to loopback, RFC1918, link-local, CGNAT and the reserved
documentation ranges if that file is absent.

Exit 2 blocks the command and returns the message to Claude.

Matching operates on a *sanitised* copy of the command with heredoc bodies and
redirect targets removed. Writing a file that merely mentions a scanning tool is
not an invocation of one, and a guard that fires on documentation gets routed
around — which disables it far more thoroughly than deleting it would.

The sanitising is deliberately narrow. It removes text that cannot be a command,
never text that could be. Anything still executable is matched exactly as
before, including targets that arrive through a variable.
"""

import ipaddress
import json
import os
import re
import sys

DEFAULT_SCOPE = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    # reserved for documentation, safe in a lab, never routed
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
]

# Binaries that can put packets on the wire at a target.
#
# The bare token "cvap" is deliberately NOT here, and its removal is the third
# false positive this guard has produced. There is no binary called `cvap` --
# the binaries are cvap-core, cvap-scanpoint and cvap-cli (CLAUDE.md) -- so the
# bare token never matched an invocation. What it did match was the database
# role, which is also called cvap, so `psql -U cvap -d cvap` was blocked as a
# scan of an unverifiable target. Each time, the workaround was to phrase the
# command differently, and a guard people route around has stopped being a
# guard. If a `cvap` binary is ever built, add it back as an exact name.
#
# The prefix class accepts quotes, = and backtick as well as / and . A safety
# audit walked past the guard with bash -c "nmap <ip>", CMD=nmap, and
# `nmap <ip>` -- none of which were preceded by a character the old class
# allowed. The block message tells the reader not to encode the address
# differently, so leaving the INVOCATION trivially re-spellable was the wrong
# half to be strict about. False-positive cost is near zero: these characters
# only ever precede a word where a command can start.
#
# Still open and deliberately so, because closing them costs false positives a
# guard cannot absorb: a hostname with no IP token (nmap scanme.example.org),
# and integer-encoded addresses (nmap 3323068417, nmap 0xC6120001). Recorded
# here rather than left implied, given this file's history of being routed
# around.
#
# The prefix class accepts / and . so that ./cvap-cli and /usr/bin/nmap match.
# Without them the guard missed the most natural way to run a locally built
# binary, which is a far larger hole than the false positive above: a path
# separator is not a word boundary. The suffix stays \s|$, so a path that merely
# CONTAINS a tool name -- docs/cvap-cli.md, internal/nmap/parser.go -- still does
# not match, because the name is followed by . or / rather than by a separator.
SCAN_TOOLS = re.compile(
    r"(?:^|[\s;&|(/.'\"`=])"
    # cvap-engine-discovery is the ONE binary in this repository that can put a
    # packet on a wire (ADR-047), and it was the one name missing here. A
    # packet-capture audit measured `/tmp/eng < job.json`, `go run
    # ./cmd/cvap-engine-discovery` and an explicit out-of-scope literal all
    # allowed, while `cvap-scanpoint` — which cannot itself send a scan packet —
    # was blocked. CLAUDE.md non-negotiable 10 did not hold for the code that
    # commit added.
    #
    # The name alone is necessary and not sufficient, and that is worth stating
    # rather than leaving to be rediscovered: a binary built to /tmp/eng matches
    # nothing here, and this engine takes its targets as JSON on stdin where no
    # regex can see them. The `<` and `cat` arms of looks_indirect below are what
    # actually catch that shape — which is why the engine is added to SCAN_TOOLS
    # rather than to SOFT_TOOLS.
    r"(cvap-scanpoint|cvap-engine-discovery|cvap-engine-\w+|cvap-cli|cvap-core|"
    r"nmap|masscan|zmap|zgrab\w*|nuclei|"
    r"hping3?|nping|arp-scan|fping|netcat|ncat|nc|telnet|ssh|"
    r"sslscan|testssl(?:\.sh)?|sqlmap|nikto|gobuster|ffuf|dirb|hydra|medusa)"
    # The suffix class mirrors the prefix for the same reason: CMD=nmap; leaves
    # the tool name followed by a semicolon, not whitespace. Widening it is
    # nearly free, because matching a tool name is not on its own enough to
    # block -- an out-of-scope target has to be present too, which is why
    # `git commit -m "add nmap parser"` stays allowed.
    r"(?:[\s;&|)'\"`]|$)"
)

# Commands that reach the network but are routine in development. For these we
# only object to a literal out-of-scope IP, not to hostnames.
SOFT_TOOLS = re.compile(r"(?:^|[\s;&|(/.'\"`=])(curl|wget|http|https)(?:[\s;&|)'\"`]|$)")

IP_TOKEN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\b")
V6_TOKEN = re.compile(r"\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(/\d{1,3})?\b")

# `<<EOF`, `<< "EOF"`, `<<-'EOF'`. The delimiter word is what we track.
HEREDOC_START = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")

# `> file`, `>>file`, `2> file`, `&> file`. The `[^\s;&|<>]+` target class means
# `2>&1` is left alone, which is correct: it names no file.
REDIRECT_TARGET = re.compile(r"(?:\d?>>?|&>)\s*(?:'[^']*'|\"[^\"]*\"|[^\s;&|<>()]+)")


def strip_heredocs(command):
    """Remove heredoc bodies, keeping the command lines that introduce them.

    The `<<` operator itself is preserved (only the delimiter word is dropped)
    so that the indirect-input check below still sees an input redirect.
    """
    lines = command.split("\n")
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        pending = [(m.group(3), m.group(1) == "-") for m in HEREDOC_START.finditer(line)]
        out.append(HEREDOC_START.sub("<< ", line))
        i += 1
        for delim, dash_form in pending:
            while i < len(lines):
                body_line = lines[i]
                # bash requires the delimiter alone on its line; `<<-` also
                # permits leading tabs.
                closing = body_line.strip() if dash_form else body_line.rstrip()
                i += 1
                if closing == delim:
                    break
            # An unterminated heredoc consumes to end of input, which is what
            # bash does too. The body stays excluded.
    return "\n".join(out)


def strip_redirect_targets(command):
    """Remove the filename side of a redirect.

    `cat > cvap-notes.md` writes a file; it does not run a scanner.
    """
    return REDIRECT_TARGET.sub(" ", command)


def sanitise(command):
    """The string all matching runs against."""
    return strip_redirect_targets(strip_heredocs(command))


def load_scope():
    root = os.environ.get("CLAUDE_PROJECT_DIR", ".")
    path = os.path.join(root, "lab", "scope.txt")
    entries = []
    if os.path.isfile(path):
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    entries.append(line)
    if not entries:
        entries = DEFAULT_SCOPE
    nets = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            pass
    return nets


def in_scope(addr, nets):
    try:
        net = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return True  # not an address we can judge
    return any(net.subnet_of(n) for n in nets if n.version == net.version)


def targets(command):
    found = set()
    for m in IP_TOKEN.finditer(command):
        found.add(m.group(1) + (m.group(2) or ""))
    for m in V6_TOKEN.finditer(command):
        tok = m.group(1)
        if tok.count(":") >= 2 and not re.fullmatch(r"[\d:]{1,5}", tok):
            found.add(tok + (m.group(2) or ""))
    return found


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    raw = (payload.get("tool_input") or {}).get("command") or ""
    if not raw:
        sys.exit(0)

    command = sanitise(raw)

    is_scan = bool(SCAN_TOOLS.search(command))
    is_soft = bool(SOFT_TOOLS.search(command))
    if not (is_scan or is_soft):
        sys.exit(0)

    nets = load_scope()
    offenders = sorted(t for t in targets(command) if not in_scope(t, nets))

    if offenders:
        print(
            "BLOCKED by lab-scope-guard: target(s) outside the authorised lab scope: "
            + ", ".join(offenders)
            + ".\nScanning tools may only be pointed at addresses listed in lab/scope.txt. "
            "Add the target there if it is genuinely yours and authorised, or use a lab "
            "address instead. Do not work around this by encoding the address differently.",
            file=sys.stderr,
        )
        sys.exit(2)

    # A scan tool with no literal address may be reading targets from a file or
    # a variable, which this guard cannot evaluate.
    if is_scan and not targets(command):
        # `|` added: this engine reads its job from stdin, so `echo '{...}' |
        # cvap-engine-discovery` carries targets no regex here can see — the same
        # unverifiable shape as `< file`, arrived at from the other side.
        looks_indirect = re.search(r"(-i\w*\s|--target|--input|\$\{?\w+|<|\||\bcat\b)", command)
        if looks_indirect:
            print(
                "BLOCKED by lab-scope-guard: scanning tool invoked with targets from a file "
                "or variable, which cannot be checked here. Pass explicit lab addresses, or "
                "run through the scan point so policy scope enforcement applies.",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
