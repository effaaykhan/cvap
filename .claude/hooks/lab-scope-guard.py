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
SCAN_TOOLS = re.compile(
    r"(?:^|[\s;&|(])"
    r"(cvap-scanpoint|cvap-cli|cvap|nmap|masscan|zmap|zgrab\w*|nuclei|"
    r"hping3?|nping|arp-scan|fping|netcat|ncat|nc|telnet|ssh|"
    r"sslscan|testssl(?:\.sh)?|sqlmap|nikto|gobuster|ffuf|dirb|hydra|medusa)"
    r"(?:\s|$)"
)

# Commands that reach the network but are routine in development. For these we
# only object to a literal out-of-scope IP, not to hostnames.
SOFT_TOOLS = re.compile(r"(?:^|[\s;&|(])(curl|wget|http|https)(?:\s|$)")

IP_TOKEN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\b")
V6_TOKEN = re.compile(r"\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(/\d{1,3})?\b")


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

    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command:
        sys.exit(0)

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
        looks_indirect = re.search(r"(-i\w*\s|--target|--input|\$\{?\w+|<|\bcat\b)", command)
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
