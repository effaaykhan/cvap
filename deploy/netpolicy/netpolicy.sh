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
#   CVAP_NP_CORE_ENDPOINTS  required. Comma-separated Core endpoints as IP
#                           literals with ports: 10.0.0.5:8443,10.0.0.5:8444
#                           ([v6]:port for IPv6). The ONLY traffic outside the
#                           ceiling. Names are refused: the exclusion must not
#                           depend on what a resolver answers later.
#   CVAP_NP_RATE_PPS        default 1000 (ADR-024's per-Scan-Point ceiling).
#   CVAP_NP_BURST           default 100.
#   CVAP_NP_VERIFY_SECONDS  default 1.
#
# Forwarding cannot be switched off from here (/proc/sys is read-only in a
# container); the holder is started with --sysctl net.ipv4.ip_forward=0 and
# the conf.all/conf.default forwarding sysctls, and refuses to run without.
#
# Fail closed, three ways:
#   - an nftables guard, installed FIRST, drops everything leaving through an
#     interface that is not in the `policed` set. `docker network connect`
#     makes an interface usable at once; until this script has policed and
#     verified it, it carries nothing.
#   - `hold` exits on any verification failure. Docker then tears down the
#     holder's network endpoints, and a Scan Point sharing this namespace is
#     left with loopback only.
#   - `verify` is the HEALTHCHECK, so an unhealthy holder is visible.
set -eu

R="${CVAP_NP_RATE_PPS:-1000}"
B="${CVAP_NP_BURST:-100}"
EVERY="${CVAP_NP_VERIFY_SECONDS:-1}"
ACTION_INDEX=1
EXCLUDE_PREF=1
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

# endpoints prints "family ip port" per configured Core endpoint, or dies.
endpoints() {
	[ -n "${CVAP_NP_CORE_ENDPOINTS:-}" ] || die "CVAP_NP_CORE_ENDPOINTS is not set; refusing to run without knowing what Core is"
	echo "$CVAP_NP_CORE_ENDPOINTS" | tr ',' '\n' | while IFS= read -r ep; do
		ep=$(echo "$ep" | tr -d ' ')
		[ -n "$ep" ] || continue
		case "$ep" in
		\[*\]:*)
			ip=${ep#\[}; ip=${ip%%\]*}; port=${ep##*\]:}; fam=ipv6
			case "$ip" in *:*) ;; *) die "not an IPv6 literal: $ep" ;; esac ;;
		*:*:*) die "IPv6 endpoints must be bracketed: $ep" ;;
		*:*)
			ip=${ep%:*}; port=${ep##*:}; fam=ip
			echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "not an IPv4 literal (names are refused): $ep" ;;
		*) die "endpoint without a port: $ep" ;;
		esac
		is_uint "$port" && [ "$port" -le 65535 ] || die "bad port in $ep"
		echo "$fam $ip $port"
	done
}

ifaces() { for d in /sys/class/net/*; do n=${d##*/}; [ "$n" = lo ] || echo "$n"; done; }

guard() {
	# The namespace-wide default-deny for unpoliced interfaces. Priority -300
	# runs it before anything else on the output hook.
	nft -f - <<-EOF
	table inet cvap_netpolicy {
		set policed { type ifname; }
		chain out {
			type filter hook output priority -300; policy accept;
			oifname "lo" accept
			oifname @policed accept
			counter drop comment "interface not policed yet"
		}
	}
	table arp cvap_netpolicy {
		set policed { type ifname; }
		chain out {
			type filter hook output priority -300; policy accept;
			oifname @policed accept
			counter drop comment "interface not policed yet"
		}
	}
	EOF
}

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
		tc filter add dev "$dev" egress pref "$EXCLUDE_PREF" protocol "$fam" flower \
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
	# Only a verified interface joins the set the guard lets through.
	verify_iface "$dev" || die "$dev could not be policed; it stays blocked"
	nft add element inet cvap_netpolicy policed "{ \"$dev\" }"
	nft add element arp cvap_netpolicy policed "{ \"$dev\" }"
	log "$dev policed: ${R} pkt/s, burst ${B}, TCP/ICMP/ICMPv6/ARP only, one segment per buffer, Core excluded"
}

# expected prints, normalised as filters() prints them, the one egress filter
# set an interface may carry: the Core exclusions, the allowed protocols into
# the shared policer, the catch-all drop. Nothing more, nothing less.
expected() {
	endpoints | while read -r fam ip port; do
		echo "$EXCLUDE_PREF $fam flower tcp $ip $port dst_ip,dst_port,eth_type,ip_proto pass"
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

verify() {
	is_uint "$R" && is_uint "$B" || die "rate and burst must be positive integers"
	a=$(tc -j actions get action police index "$ACTION_INDEX" 2>/dev/null) || die "the police action does not exist"
	ok=$(echo "$a" | jq "[.[] | .actions[]? | select(.pkts_rate == $R and .pkts_burst == $B
		and .control_action.type == \"drop\")] | length")
	[ "$ok" = 1 ] || die "the police action is not pkts_rate $R pkts_burst $B drop-on-exceed"
	nft list chain inet cvap_netpolicy out >/dev/null 2>&1 || die "the nftables guard is missing"
	nft list chain arp cvap_netpolicy out >/dev/null 2>&1 || die "the ARP guard is missing"
	forwarding_off
	n=0
	for dev in $(ifaces); do
		n=$((n + 1))
		verify_iface "$dev" || die "$dev fails verification"
		nft get element inet cvap_netpolicy policed "{ \"$dev\" }" >/dev/null 2>&1 ||
			die "$dev is not in the policed set"
	done
	[ "$n" -gt 0 ] || die "no egress interface to police"
	return 0
}

attach() {
	action
	for dev in $(ifaces); do
		nft get element inet cvap_netpolicy policed "{ \"$dev\" }" >/dev/null 2>&1 || police_iface "$dev"
	done
	verify
}

hold() {
	is_uint "$R" && is_uint "$B" && is_uint "$EVERY" || die "rate, burst and interval must be positive integers"
	endpoints >/dev/null
	forwarding_off
	guard
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
