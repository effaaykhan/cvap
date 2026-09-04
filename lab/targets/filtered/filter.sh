#!/bin/sh
# Drop inbound SYNs on everything except the port we leave open, so the host is
# discoverable but most of it is silent.
#
# DROP rather than REJECT: a REJECT sends an ICMP unreachable or a RST, which is
# an ANSWER — the scanner learns the port is closed immediately and no
# retransmission happens. Dropping is what a firewall in front of an appliance
# does and what produces the retransmit train.
set -e
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Something to find, so the host is not simply invisible: host discovery needs
# one answering port or the target is indistinguishable from an empty address,
# which is a different test.
while true; do
  nc -l -p 22 -e /bin/echo "SSH-2.0-lab-filtered" 2>/dev/null || sleep 1
done
