#!/bin/sh
# netpolicy — the Scan Point network-policy holder (ADR-110).
#
# Enforces, per Scan Point network namespace N and every interval of length D:
#
#     packets leaving N, other than TCP to the Core endpoints E  <=  B + R*D
#
# with a kernel tc `police` action (R packets/s, burst B, drop on exceed) shared
# by every non-loopback interface of N, so it is ONE bucket however many
# networks the Scan Point is attached to. The kernel applies it per packet at
# the egress hook; no user-space process, and so no scheduler, is in the path.
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
POLICE_PREF=10

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

police_iface() {
	dev=$1
	ethtool -K "$dev" tso off gso off >/dev/null 2>&1 || true
	tc qdisc add dev "$dev" clsact 2>/dev/null || true
	tc filter del dev "$dev" egress 2>/dev/null || true
	endpoints | while read -r fam ip port; do
		tc filter add dev "$dev" egress pref "$EXCLUDE_PREF" protocol "$fam" flower \
			ip_proto tcp dst_ip "$ip" dst_port "$port" action pass
	done
	tc filter add dev "$dev" egress pref "$POLICE_PREF" matchall action police index "$ACTION_INDEX"
	# Only a verified interface joins the set the guard lets through.
	verify_iface "$dev" || die "$dev could not be policed; it stays blocked"
	nft add element inet cvap_netpolicy policed "{ \"$dev\" }"
	nft add element arp cvap_netpolicy policed "{ \"$dev\" }"
	log "$dev policed: ${R} pkt/s, burst ${B}, Core excluded"
}

# verify_iface checks one interface's offload and its exact egress filter set.
verify_iface() {
	dev=$1
	off=$(ethtool -k "$dev" 2>/dev/null) || { echo "netpolicy: $dev: ethtool -k failed" >&2; return 1; }
	echo "$off" | grep -q '^tcp-segmentation-offload: off' || { echo "netpolicy: $dev: TSO is not off" >&2; return 1; }
	echo "$off" | grep -q '^generic-segmentation-offload: off' || { echo "netpolicy: $dev: GSO is not off" >&2; return 1; }
	f=$(tc -j filter show dev "$dev" egress 2>/dev/null) || { echo "netpolicy: $dev: no clsact egress" >&2; return 1; }
	police=$(echo "$f" | jq "[.[] | select(.kind == \"matchall\" and .pref == $POLICE_PREF)
		| .options.actions[]? | select(.kind == \"police\" and .index == $ACTION_INDEX)] | length")
	[ "$police" = 1 ] || { echo "netpolicy: $dev: the shared police action is not attached" >&2; return 1; }
	# Exactly the configured exclusions and nothing else: a second pass rule, or
	# one wider than an endpoint, would be a bypass of the ceiling.
	want=$(endpoints | awk '{print $2" "$3}' | sort)
	have=$(echo "$f" | jq -r ".[] | select(.options.keys != null)
		| \"\(.pref) \(.options.keys.ip_proto // \"-\") \(.options.keys.dst_ip // \"-\") \(.options.keys.dst_port // \"-\") \(.options.actions[0].control_action.type // .options.actions[0].kind)\"" | sort)
	got=$(echo "$have" | awk -v p="$EXCLUDE_PREF" '$1==p && $2=="tcp" && $5=="pass" {print $3" "$4}' | sort)
	[ "$got" = "$want" ] || { echo "netpolicy: $dev: Core exclusions are not exactly E (have: $have)" >&2; return 1; }
	other=$(echo "$f" | jq "[.[] | select(.options != null) | select(.pref != $POLICE_PREF and .pref != $EXCLUDE_PREF)] | length")
	[ "$other" = 0 ] || { echo "netpolicy: $dev: unexpected egress filters" >&2; return 1; }
	return 0
}

verify() {
	is_uint "$R" && is_uint "$B" || die "rate and burst must be positive integers"
	a=$(tc -j actions get action police index "$ACTION_INDEX" 2>/dev/null) || die "the police action does not exist"
	ok=$(echo "$a" | jq "[.[] | .actions[]? | select(.pkts_rate == $R and .pkts_burst == $B
		and .control_action.type == \"drop\")] | length")
	[ "$ok" = 1 ] || die "the police action is not pkts_rate $R pkts_burst $B drop-on-exceed"
	nft list chain inet cvap_netpolicy out >/dev/null 2>&1 || die "the nftables guard is missing"
	nft list chain arp cvap_netpolicy out >/dev/null 2>&1 || die "the ARP guard is missing"
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
