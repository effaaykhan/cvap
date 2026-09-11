# A plain, modern sshd. It offers no weak algorithms; its only labelled finding is
# management-interface-untrusted-zone, and that comes entirely from being observed
# from segment-b (labelled external in the corpus), not from anything about the
# host. It proves exposure is a property of the vantage point (ADR-008), not the
# service.
#
# It is also the credentialed-host target for the end-to-end suite (ADR-091):
# a `lab` account with an ed25519 key GENERATED AT BUILD TIME — nothing is
# committed — and left at /lab/id_ed25519 for `docker cp`, which is how
# test/e2e obtains it (the same way the corpus asks a container about itself).
# Debian, so the engine's dpkg read has a real inventory to report; the test
# compares that report against `dpkg-query` run inside this container.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A \
    && useradd -m -s /bin/sh lab \
    && mkdir -p /lab /home/lab/.ssh \
    && ssh-keygen -q -t ed25519 -N "" -C "cvap-lab" -f /lab/id_ed25519 \
    && cp /lab/id_ed25519.pub /home/lab/.ssh/authorized_keys \
    && chown -R lab:lab /home/lab/.ssh && chmod 700 /home/lab/.ssh && chmod 600 /home/lab/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
