#!/bin/sh
# netpolicy — the Scan Point network-policy holder (ADR-110).
#
# Enforces, per Scan Point network namespace N and every interval of length D:
#
#     packets leaving N, other than TCP to the Core endpoints E  <=  B + R*D
#
# with a kernel tc `police` action (R packets/s, burst B, drop on exceed) shared
# by every non-loopback interface of N, so it is ONE bucket however many
# networks the Scan Point is attached to. The kernel applies it at the egress
# hook; no user-space process, and so no scheduler, is in the path.
#
# The policer charges once per buffer (skb), and the wire carries packets. They
# are the same thing only because of what this script also establishes, and
# `verify` checks, on every interface:
#   - segmentation: gso_max_segs 1, gso_max_size <= MTU, and every TX
#     segmentation, scatter-gather and GRO feature off. TCP builds its buffers
#     to gso_max_segs, so each is one packet; IP fragments are made before the
#     hook, so each is its own buffer.
#   - protocol default-deny: only TCP, ICMP, ICMPv6 and ARP reach the policer,
#     and a final catch-all drops everything else. UDP_SEGMENT turns one buffer
#     into up to 64 packets AFTER the hook whatever the segmentation settings,
#     so UDP is dropped, never counted. So is every protocol not named here.
#   - forwarding off (IPv4 and IPv6, all/default/each interface), so no buffer
#     merged elsewhere is forwarded out through the hook.
#
#   hold     set everything up, verify, then keep verifying (the container's
#            main process). Exits non-zero the moment anything is wrong.
#   attach   police interfaces added since (after `docker network connect`).
#   verify   check every precondition; non-zero on any failure. Also the
#            image's HEALTHCHECK.
#
# Configuration (environment):
#   CVAP_NP_CORE_ENDPOINTS  required. Comma-separated Core endpoints as single
#                           IP literals with ports: 10.0.0.5:8443,10.0.0.5:8444
#                           ([v6]:port for IPv6; both families may be mixed).
#                           The ONLY traffic outside the ceiling. Names,
#                           prefixes, zones and the unspecified address are
#                           refused: the exclusion must not depend on what a
#                           resolver answers later, and must never be wider
#                           than one host.
#   CVAP_NP_RATE_PPS        default and MAXIMUM 1000 (ADR-024's per-Scan-Point
#                           ceiling: a deployment may lower it, never raise it).
#   CVAP_NP_BURST           default and maximum 100.
#   CVAP_NP_VERIFY_SECONDS  default 1, maximum 5. This bounds how long a fault
#                           can go unnoticed, so it is not an operator's to widen.
#
# Forwarding cannot be switched off from here (/proc/sys is read-only in a
# container); the holder is started with --sysctl net.ipv4.ip_forward=0 and
# the conf.all/conf.default forwarding sysctls, and refuses to run without.
#
# Fail closed, three ways:
#   - an nftables guard, installed FIRST, drops everything leaving through an
#     interface whose INDEX is not in the `policed` set. `docker network
#     connect` makes an interface usable at once; until this script has policed
#     and verified it, it carries nothing. The set is keyed by interface index,
#     not name: a disconnected and reconnected network comes back under the
#     same name (eth1) with a NEW index, no filters and offload on, so a name
#     in the set would have let it straight through (measured: 4,594 UDP
#     superpackets in 0.59 s before the next verify noticed). The kernel never
#     reuses an index while the namespace lives, and every cycle prunes indices
#     that no longer exist and re-verifies every member before trusting it.
#     A pass is judged against a STABLE interface set (names, indices and
#     up/down flags): an interface that vanishes, appears or comes up while
#     the pass runs (`docker network disconnect` landing between `ifaces`
#     listing it and `ethtool -k` reading it; `connect` moving in an interface
#     that is renamed and brought up moments later, with no qdisc yet) is not a
#     failed check but a changed set, and the pass is run again at once, at
#     most MAX_PASSES times in a row. A set that looks unchanged after a
#     failed pass is given SETTLE seconds to show otherwise. A set that keeps
#     changing, or a check that fails on a set that did not change, is fatal:
#     a fault is fatal within EVERY + SETTLE seconds.
#   - `hold` exits on any verification failure. Docker then tears down the
#     holder's network endpoints, and a Scan Point sharing this namespace is
#     left with loopback only.
#   - `verify` is the HEALTHCHECK, so an unhealthy holder is visible.
set -eu
# fd 3 is the holder's stdout. A verify pass runs in a subshell whose stderr is
# captured (so a failure can be judged before it is fatal) while its log lines
# go straight through here.
exec 3>&1

R="${CVAP_NP_RATE_PPS:-1000}"
B="${CVAP_NP_BURST:-100}"
EVERY="${CVAP_NP_VERIFY_SECONDS:-1}"
MAX_R=1000
MAX_B=100
MAX_EVERY=5
# How many times in a row a verify pass may find the interface set changed
# under it before that itself is fatal, and how long (seconds) a set that looks
# unchanged after a failed pass is given to show that it is still being changed
# (an interface moved in and not yet renamed or brought up). See attach.
MAX_PASSES=5
SETTLE=1
ACTION_INDEX=1
EXCLUDE_PREF_IP=1
EXCLUDE_PREF_IPV6=2
DENY_PREF=100

# The allowed protocols, each sent to the shared policer: "pref protocol kind ip_proto".
allowed() {
	cat <<-EOF
	10 ip flower tcp
	11 ip flower icmp
	12 ipv6 flower tcp
	13 ipv6 flower icmpv6
	14 arp matchall -
	EOF
}

# The segmentation, scatter-gather and GRO features that must all be off.
SEG_FEATURES='(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|scatter-gather|tx-[a-z0-9_-]*segmentation|tx-gso-list|tx-scatter-gather[a-z-]*|rx-gro-list|rx-udp-gro-forwarding)'

die() { echo "netpolicy: $*" >&2; exit 1; }
log() { echo "netpolicy: $*"; }

is_uint() { case "$1" in '' | *[!0-9]*) return 1 ;; *) [ "$1" -gt 0 ] ;; esac; }

# limits: R, B and the verify interval are positive integers at or below the
# platform maximums. ADR-024: a deployment may lower a ceiling and never raise
# it, and a holder that reported itself healthy at any R would make the
# invariant whatever the environment said.
limits() {
	is_uint "$R" && is_uint "$B" && is_uint "$EVERY" || die "rate, burst and interval must be positive integers"
	[ "$R" -le "$MAX_R" ] || die "CVAP_NP_RATE_PPS=$R is above the platform ceiling $MAX_R (ADR-024: lower only)"
	[ "$B" -le "$MAX_B" ] || die "CVAP_NP_BURST=$B is above the platform burst $MAX_B (lower only)"
	[ "$EVERY" -le "$MAX_EVERY" ] || die "CVAP_NP_VERIFY_SECONDS=$EVERY is above the maximum $MAX_EVERY"
}

# is_ipv4 accepts exactly one dotted quad with each octet 0-255, no leading zeros
# (iproute2 reads 010 as octal), and not the unspecified address.
is_ipv4() {
	echo "$1" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$' || return 1
	[ "$1" != "0.0.0.0" ]
}

# is_ipv6 accepts one address: hex and colons only; no prefix, no zone, at most
# one "::", 2-8 groups. Not "::" (unspecified). An embedded-IPv4 spelling
# (::ffff:1.2.3.4 and its relatives) is REFUSED: Go unmaps it to v4 but the
# holder would install a v6 exemption from the literal, so the two layers would
# disagree about one address (ADR-111). Write Core as a plain IPv4 or IPv6.
# is_v4mapped reports (exit 0) whether its argument is an IPv4-mapped IPv6
# address in ANY spelling: the dotted ::ffff:10.0.0.5, the all-hex
# ::ffff:0a00:0005 / ::ffff:a00:5, a fully expanded 0:0:0:0:0:ffff:0a00:0005,
# and partially compressed forms. It expands :: and a trailing dotted quad to
# the full eight groups and tests that the first five are zero and the sixth is
# ffff - the semantic test, so no spelling slips the way a dotted-quad text
# match did. Such an address is refused as a Core endpoint (see is_ipv6).
is_v4mapped() {
	echo "$1" | awk '
	{
		addr = tolower($0)
		if (addr ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
			n = split(addr, dp, ":")
			if (split(dp[n], o, ".") == 4) {
				addr = ""
				for (i = 1; i < n; i++) addr = addr dp[i] ":"
				addr = addr sprintf("%x:%x", o[1]*256 + o[2], o[3]*256 + o[4])
			}
		}
		if (index(addr, "::")) {
			split(addr, h, "::")
			ln = (h[1] == "" ? 0 : split(h[1], L, ":"))
			rn = (h[2] == "" ? 0 : split(h[2], R, ":"))
			fill = 8 - ln - rn
			if (fill < 1) exit 1
			j = 0
			for (i = 1; i <= ln; i++) g[++j] = L[i]
			for (i = 1; i <= fill; i++) g[++j] = "0"
			for (i = 1; i <= rn; i++) g[++j] = R[i]
			ng = j
		} else {
			ng = split(addr, g, ":")
		}
		if (ng != 8) exit 1
		for (i = 1; i <= 8; i++) { sub(/^0+/, "", g[i]); if (g[i] == "") g[i] = "0" }
		if (g[1]=="0"&&g[2]=="0"&&g[3]=="0"&&g[4]=="0"&&g[5]=="0"&&g[6]=="ffff") exit 0
		exit 1
	}'
}

is_ipv6() {
	case "$1" in *[!0-9a-fA-F:.]*) return 1 ;; esac
	case "$1" in *:*:*) ;; *) return 1 ;; esac
	case "$1" in *:::*) return 1 ;; esac
	[ "$(echo "$1" | awk -F'::' '{print NF-1}')" -le 1 ] || return 1
	[ "$1" != "::" ] || return 1
	# An IPv4-mapped IPv6 address, in any spelling, is refused: the Go layer
	# unmaps it to v4 while the holder would install it as an IPv6 exemption from
	# the literal, so the two layers would disagree about one address (ADR-111).
	# Caught semantically, not only by a dotted quad, so the all-hex
	# ::ffff:0a00:0005 form is refused too.
	! is_v4mapped "$1" || return 1
	groups=$(echo "$1" | tr ':' '\n' | grep -c . || true)
	[ "$groups" -le 8 ] || return 1
	for g in $(echo "$1" | tr ':' ' '); do
		case "$g" in
		*.*) return 1 ;;  # embedded IPv4 (::ffff:1.2.3.4) refused, ADR-111
		*) [ "${#g}" -le 4 ] || return 1 ;;
		esac
	done
}

# endpoints prints "family ip port" per configured Core endpoint, or dies.
endpoints() {
	[ -n "${CVAP_NP_CORE_ENDPOINTS:-}" ] || die "CVAP_NP_CORE_ENDPOINTS is not set; refusing to run without knowing what Core is"
	echo "$CVAP_NP_CORE_ENDPOINTS" | tr ',' '\n' | while IFS= read -r ep; do
		ep=$(echo "$ep" | tr -d ' ')
		[ -n "$ep" ] || continue
		case "$ep" in
		\[*\]:*)
			ip=${ep#\[}; ip=${ip%%\]*}; port=${ep##*\]:}; fam=ipv6
			is_ipv6 "$ip" || die "not a single IPv6 address (no names, prefixes, zones or ::): $ep" ;;
		*:*:*) die "IPv6 endpoints must be bracketed: $ep" ;;
		*:*)
			ip=${ep%:*}; port=${ep##*:}; fam=ip
			is_ipv4 "$ip" || die "not a single IPv4 address (names and 0.0.0.0 are refused): $ep" ;;
		*) die "endpoint without a port: $ep" ;;
		esac
		is_uint "$port" && [ "$port" -le 65535 ] || die "bad port in $ep"
		echo "$fam $ip $port"
	done
}

# ifaces lists the egress interfaces: every interface but loopback that is UP.
# A DOWN interface carries nothing and cannot verify - it has no root qdisc
# until its first up - and Docker moves a new interface in DOWN, under a
# temporary name, and brings it up in a later step that under daemon load came
# more than a second later (measured: `vethd5ad60f: qdiscs are [clsact], not
# exactly clsact + noqueue` ... `verification failed on interfaces [eth0:2:0x1003
# vethd5ad60f:133:0x1002 ] (pass 1)` - a set that had not changed, judged as a
# failed check). It joins the policed set at its first UP pass; until then the
# guard drops anything its index would carry, and DOWN it carries nothing.
#
# listing prints the egress interfaces as name:index:flags on one line. ifaces
# prints their names and, while SEEN names a file (inside an attach pass),
# appends the listing to it: a pass that fails is judged against EVERY listing
# it took, from the snapshot before it to the one after, not only the two
# ends - an interface that arrived after the first snapshot and vanished
# before the last left both snapshots equal while the pass had seen it
# (measured: `eth1 (ifindex ) is not in the policed set` ... `verification
# failed on interfaces [eth0:2:0x1003 ] (pass 1)`, on the 59th reconnect cycle).
listing() {
	for d in /sys/class/net/*; do
		n=${d##*/}
		[ "$n" = lo ] && continue
		f=$(cat "$d/flags" 2>/dev/null) || continue
		[ $((f & 1)) -eq 1 ] || continue
		i=$(cat "$d/ifindex" 2>/dev/null) || continue
		printf '%s:%s:%s ' "$n" "$i" "$f"
	done
}
ifaces() {
	l=$(listing)
	[ -n "${SEEN:-}" ] && printf '%s\n' "$l" >> "$SEEN"
	for e in $l; do echo "${e%%:*}"; done
	return 0
}
ifindex() { cat "/sys/class/net/$1/ifindex"; }

# exclude_pref: one tc pref per address family. tc binds a pref to one protocol,
# so a mixed E on a single pref fails to install.
exclude_pref() { [ "$1" = ipv6 ] && echo "$EXCLUDE_PREF_IPV6" || echo "$EXCLUDE_PREF_IP"; }

# policed_indices prints the interface indices currently in the guard set. nft
# renders an iface_index element as its current NAME, so the indices are read
# back through /sys rather than parsed from nft.
policed_indices() {
	nft -j list set inet cvap_netpolicy policed 2>/dev/null |
		jq -r '.nftables[] | select(.set) | .set.elem // [] | .[] | if type == "object" then .elem.val else . end' |
		while IFS= read -r e; do
			case "$e" in
			'' ) ;;
			*[!0-9]*) [ -e "/sys/class/net/$e/ifindex" ] && cat "/sys/class/net/$e/ifindex" || echo "gone:$e" ;;
			*) echo "$e" ;;
			esac
		done
}
in_policed() { nft get element inet cvap_netpolicy policed "{ $1 }" >/dev/null 2>&1; }

guard() {
	# The namespace-wide default-deny for unpoliced interfaces. Priority -300
	# runs it before anything else on the output hook.
	nft -f - <<-EOF
	table inet cvap_netpolicy {
		set policed { type iface_index; }
		chain out {
			type filter hook output priority -300; policy accept;
			oif "lo" accept
			oif @policed accept
			counter drop comment "interface not policed yet"
		}
	}
	table arp cvap_netpolicy {
		set policed { type iface_index; }
		chain out {
			type filter hook output priority -300; policy accept;
			oif @policed accept
			counter drop comment "interface not policed yet"
		}
	}
	EOF
}

# action creates the shared police action once, at start. It is never
# re-created later: an action that has vanished means something with
# NET_ADMIN removed it, and that is a failure to exit on, not repair.
action() {
	tc actions get action police index "$ACTION_INDEX" >/dev/null 2>&1 && return 0
	tc actions add action police pkts_rate "$R" pkts_burst "$B" conform-exceed drop index "$ACTION_INDEX"
}

segmentation_off() {
	dev=$1
	for f in $(ethtool -k "$dev" | grep -E "^[[:space:]]*$SEG_FEATURES: on\$" | cut -d: -f1 | tr -d ' \t'); do
		ethtool -K "$dev" "$f" off >/dev/null 2>&1 || true
	done
	ethtool -K "$dev" sg off tso off gso off gro off >/dev/null 2>&1 || true
	ip link set dev "$dev" gso_max_segs 1 gso_max_size "$(cat "/sys/class/net/$dev/mtu")"
}

police_iface() {
	dev=$1
	segmentation_off "$dev"
	tc qdisc add dev "$dev" clsact 2>/dev/null || true
	tc filter del dev "$dev" egress 2>/dev/null || true
	endpoints | while read -r fam ip port; do
		tc filter add dev "$dev" egress pref "$(exclude_pref "$fam")" protocol "$fam" flower \
			ip_proto tcp dst_ip "$ip" dst_port "$port" action pass
	done
	allowed | while read -r pref proto kind ipp; do
		if [ "$kind" = flower ]; then
			tc filter add dev "$dev" egress pref "$pref" protocol "$proto" flower ip_proto "$ipp" \
				action police index "$ACTION_INDEX"
		else
			tc filter add dev "$dev" egress pref "$pref" protocol "$proto" matchall action police index "$ACTION_INDEX"
		fi
	done
	tc filter add dev "$dev" egress pref "$DENY_PREF" protocol all matchall action drop
	# Only a verified interface joins the set the guard lets through, by index.
	verify_iface "$dev" || die "$dev could not be policed; it stays blocked"
	idx=$(ifindex "$dev")
	nft add element inet cvap_netpolicy policed "{ $idx }"
	nft add element arp cvap_netpolicy policed "{ $idx }"
	log "$dev (ifindex $idx) policed: ${R} pkt/s, burst ${B}, TCP/ICMP/ICMPv6/ARP only, one segment per buffer, Core excluded"
}

# expected prints, normalised as filters() prints them, the one egress filter
# set an interface may carry: the Core exclusions, the allowed protocols into
# the shared policer, the catch-all drop. Nothing more, nothing less.
expected() {
	endpoints | while read -r fam ip port; do
		echo "$(exclude_pref "$fam") $fam flower tcp $ip $port dst_ip,dst_port,eth_type,ip_proto pass"
	done
	allowed | while read -r pref proto kind ipp; do
		if [ "$kind" = flower ]; then
			echo "$pref $proto flower $ipp - - eth_type,ip_proto police$ACTION_INDEX"
		else
			echo "$pref $proto matchall - - - - police$ACTION_INDEX"
		fi
	done
	echo "$DENY_PREF all matchall - - - - drop"
}

filters() {
	tc -j filter show dev "$1" egress | jq -r '.[] | select(.options != null)
		| [.options.actions[]?] as $a | (.options.keys // {}) as $k
		| "\(.pref) \(.protocol) \(.kind) \($k.ip_proto // "-") \($k.dst_ip // "-") \($k.dst_port // "-") \($k | keys | join(",") | if . == "" then "-" else . end) \(
			if ($a | length) != 1 then "actions:\($a | length)"
			elif $a[0].kind == "police" then "police\($a[0].index)"
			else $a[0].control_action.type end)"'
}

# verify_iface checks one interface's segmentation state and its exact egress
# filter set.
verify_iface() {
	dev=$1
	off=$(ethtool -k "$dev" 2>/dev/null) || { echo "netpolicy: $dev: ethtool -k failed" >&2; return 1; }
	on=$(echo "$off" | grep -E "^[[:space:]]*$SEG_FEATURES: on" | tr -d '\t' | tr '\n' ' ')
	[ -z "$on" ] || { echo "netpolicy: $dev: segmentation features still on: $on" >&2; return 1; }
	l=$(ip -d -j link show dev "$dev" 2>/dev/null) || { echo "netpolicy: $dev: ip link failed" >&2; return 1; }
	seg=$(echo "$l" | jq -r '.[0] | "\(.gso_max_segs) \(.gso_max_size) \(.gso_ipv4_max_size // .gso_max_size) \(.mtu)"')
	echo "$seg" | awk '{exit !($1 == 1 && $2 <= $4 && $3 <= $4)}' ||
		{ echo "netpolicy: $dev: gso_max_segs/gso_max_size/gso_ipv4_max_size/mtu are $seg, not 1 and <= mtu" >&2; return 1; }
	# The root qdisc must be the default: a classful or netem root could
	# clone or reorder AFTER classification, turning one charge into several
	# packets. Only clsact (the hook itself) may sit beside it.
	q=$(tc -j qdisc show dev "$dev" 2>/dev/null | jq -r '[.[] | .kind] | sort | join(",")')
	[ "$q" = "clsact,noqueue" ] || { echo "netpolicy: $dev: qdiscs are [$q], not exactly clsact + noqueue" >&2; return 1; }
	have=$(filters "$dev" 2>/dev/null | sort) || { echo "netpolicy: $dev: no clsact egress" >&2; return 1; }
	want=$(expected | sort)
	[ "$have" = "$want" ] || { echo "netpolicy: $dev: egress filters are not exactly the policy. have:
$have
want:
$want" >&2; return 1; }
	return 0
}

# forwarding_off: no interface of N forwards, IPv4 or IPv6.
forwarding_off() {
	[ -r /proc/sys/net/ipv4/ip_forward ] || die "cannot read net.ipv4.ip_forward"
	for f in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv6/conf/*/forwarding; do
		[ -e "$f" ] || continue
		[ "$(cat "$f")" = 0 ] || die "forwarding is on ($f); start the holder with --sysctl net.ipv4.ip_forward=0 and the conf.all/conf.default forwarding sysctls"
	done
}

# guard_intact: both guard chains exist with their exact rules - an accept for
# the policed set and a final drop - and the inet one also accepts loopback.
guard_intact() {
	for fam in inet arp; do
		r=$(nft -j list chain "$fam" cvap_netpolicy out 2>/dev/null | jq -r '
			[.nftables[] | select(.rule) | .rule.expr | map(keys[0]) | join("+")] | join(" ")') ||
			die "the $fam guard is missing"
		case "$fam" in
		inet) want="match+accept match+accept counter+drop" ;;
		arp) want="match+accept counter+drop" ;;
		esac
		[ "$r" = "$want" ] || die "the $fam guard's rules are [$r], not [$want]"
		hook=$(nft -j list chain "$fam" cvap_netpolicy out | jq -r '.nftables[] | select(.chain) | .chain | "\(.hook) \(.prio) \(.policy)"')
		[ "$hook" = "output -300 accept" ] || die "the $fam guard hook is [$hook], not output -300 accept"
	done
}

verify() {
	limits
	a=$(tc -j actions get action police index "$ACTION_INDEX" 2>/dev/null) || die "the police action does not exist"
	ok=$(echo "$a" | jq "[.[] | .actions[]? | select(.pkts_rate == $R and .pkts_burst == $B
		and .control_action.type == \"drop\")] | length")
	[ "$ok" = 1 ] || die "the police action is not pkts_rate $R pkts_burst $B drop-on-exceed"
	guard_intact
	forwarding_off
	# Every index in the guard set must be a live interface that verifies, and
	# every live interface must be in the set. Indices are never reused while
	# the namespace lives, so a stale index can only mean a vanished interface.
	for e in $(policed_indices); do
		case "$e" in gone:*) die "the policed set names an interface that no longer exists (${e#gone:})" ;; esac
		found=0
		for dev in $(ifaces); do [ "$(ifindex "$dev")" = "$e" ] && found=1; done
		[ "$found" = 1 ] || die "the policed set holds index $e, which is not a live egress interface"
	done
	n=0
	for dev in $(ifaces); do
		n=$((n + 1))
		verify_iface "$dev" || die "$dev fails verification"
		idx=$(ifindex "$dev" 2>/dev/null) || die "$dev vanished during verification"
		in_policed "$idx" || die "$dev (ifindex $idx) is not in the policed set"
	done
	[ "$n" -gt 0 ] || die "no egress interface to police"
	return 0
}

# prune removes from the guard set every index that no longer names a live
# interface, so a vanished interface's index cannot linger. (It cannot be
# reused either; this keeps the set an exact statement of what is policed.)
prune() {
	for e in $(policed_indices); do
		case "$e" in gone:*) continue ;; esac
		live=0
		for dev in $(ifaces); do [ "$(ifindex "$dev")" = "$e" ] && live=1; done
		if [ "$live" = 0 ]; then
			nft delete element inet cvap_netpolicy policed "{ $e }" 2>/dev/null || true
			nft delete element arp cvap_netpolicy policed "{ $e }" 2>/dev/null || true
			log "pruned ifindex $e from the policed set (interface gone)"
		fi
	done
}

# snapshot is the listing taken at the two ends of a pass, so a pass can tell a
# set that changed under it from a check that failed. ifaces lists only UP
# interfaces, so one that comes up, or goes down, during a pass is a changed
# set, not a failed check; the flags are printed so the log says which.
snapshot() { listing; }

# pass is one attach-and-verify pass over the interfaces as they are now.
pass() {
	prune
	for dev in $(ifaces); do
		idx=$(ifindex "$dev" 2>/dev/null) || continue  # vanished since listed; the snapshot says so
		in_policed "$idx" || police_iface "$dev"
	done
	verify
}

# attach polices every interface that is not yet in the set, then verifies
# everything. An interface already in the set is re-verified by `verify`, not
# trusted; the police action is checked, not re-created.
#
# The pass runs in a subshell: a `die` inside it ends the pass, not the holder,
# and its stderr is kept. If the pass failed and the interface set changed
# anywhere between the snapshot before it and the one after - any two adjacent
# listings differ - the failure is a transient of a changing set, measured
# three ways: `eth1: ethtool -k failed` (eth1 vanished between `ifaces` listing
# it and `ethtool` reading it, fifth cycle); `eth1 (ifindex ) is not in the
# policed set` (eth1 arrived after the first snapshot and vanished before the
# last, so the two ends agreed, 59th cycle); and, before DOWN interfaces were
# left out of the listing, `vethd5ad60f: qdiscs are [clsact]` on an interface
# Docker had not yet brought up. The pass is then run again on the set as it is
# now. A set that looks unchanged right after the failure is given SETTLE
# seconds and looked at once more, a second line behind the listing rule.
# Nothing is admitted in between: the guard drops everything leaving through an
# interface whose index is not in the set, and only a verified interface is
# ever added. A set that changes under MAX_PASSES consecutive passes, or a
# failure on a set that did not change, exits the holder.
attach() {
	tc actions get action police index "$ACTION_INDEX" >/dev/null 2>&1 || die "the shared police action is gone"
	n=0
	SEEN=$(mktemp) || die "cannot create the listing file"
	while :; do
		: > "$SEEN"
		before=$(snapshot)
		if err=$( { pass; } 2>&1 1>&3 ); then
			rm -f "$SEEN"
			SEEN=
			return 0
		fi
		after=$(snapshot)
		changed=0
		prev=$before
		while IFS= read -r l; do
			[ "$l" = "$prev" ] || changed=1
			prev=$l
		done < "$SEEN"
		[ "$after" = "$prev" ] || changed=1
		if [ "$changed" = 0 ]; then
			sleep "$SETTLE"
			after=$(snapshot)
			[ "$after" = "$before" ] || changed=1
		fi
		n=$((n + 1))
		if [ "$changed" = 1 ] && [ "$n" -le "$MAX_PASSES" ]; then
			log "the interfaces changed during a verify pass [$before] -> [$after]; re-verifying (pass $n)"
			continue
		fi
		printf '%s\n' "$err" >&2
		die "verification failed on interfaces [$after] (pass $n)"
	done
}

hold() {
	limits
	endpoints >/dev/null
	forwarding_off
	guard
	action
	attach
	log "ready: $(ifaces | tr '\n' ' ')"
	while :; do
		sleep "$EVERY"
		attach
	done
}

case "${1:-hold}" in
hold) hold ;;
attach) attach && log "verified" ;;
verify) verify ;;
*) die "usage: netpolicy [hold|attach|verify]" ;;
esac
