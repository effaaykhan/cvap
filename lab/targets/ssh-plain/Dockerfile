# A plain, modern sshd. It offers no weak algorithms; its only labelled finding is
# management-interface-untrusted-zone, and that comes entirely from being observed
# from segment-b (labelled external in the corpus), not from anything about the
# host. It proves exposure is a property of the vantage point (ADR-008), not the
# service.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
