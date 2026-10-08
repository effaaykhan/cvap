# The Scan Point network-policy holder (ADR-110).
#
# A separate, minimal image because it is the ONE thing in a Scan Point's network
# namespace that holds NET_ADMIN, and the Scan Point image (distroless, nonroot)
# must keep holding nothing. It owns the namespace, installs the kernel packet
# ceiling on every egress interface, and stays running to keep it verified; the
# Scan Point joins it with `--network container:<holder>`.
#
# Pinned by digest rather than tag, like the migrate image in the Makefile: the
# thing that enforces a safety ceiling must not change underneath a deployment
# because a tag moved (ADR-025).
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# tc (iproute2), ethtool for segmentation offload, nftables for the fail-closed
# guard, jq so verification reads tc's JSON instead of scraping its text.
RUN apk add --no-cache iproute2-tc ethtool nftables jq

COPY netpolicy.sh /usr/local/bin/netpolicy
RUN chmod 0755 /usr/local/bin/netpolicy

HEALTHCHECK --interval=5s --timeout=3s --retries=1 CMD ["/usr/local/bin/netpolicy", "verify"]
ENTRYPOINT ["/usr/local/bin/netpolicy"]
CMD ["hold"]
