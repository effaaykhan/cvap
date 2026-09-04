# A FILTERED host: reachable at layer 2, silently dropping SYNs.
#
# The lab had none, and that mattered more than it looked. Every other target
# either answers or refuses instantly, so the SYN-retransmit path — the one a
# packet-capture audit measured at 2.94 packets per connect attempt — was never
# exercised by anything. The safety gate's packet-budget assertion could not
# fail against this lab even with the accounting sabotaged.
#
# An unassigned address in the subnet is NOT this: ARP fails and the connect
# returns EHOSTUNREACH with no SYN on the wire at all. A filtered host has to
# accept the packet at IP level and drop it, which needs a real container and a
# DROP rule.
#
# It is also what "timeout is not the same as closed" means in practice, and
# what makes the difference between a fragile device and an absent one testable.
FROM alpine:3.20
RUN apk add --no-cache iptables
COPY filter.sh /filter.sh
RUN chmod +x /filter.sh
ENTRYPOINT ["/filter.sh"]
