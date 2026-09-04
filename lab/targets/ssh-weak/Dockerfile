# A real sshd re-enabling the legacy algorithms modern OpenSSH ships disabled:
# ssh-rsa (SHA-1 host-key signature) and diffie-hellman-group1-sha1. The engine
# reads what the server OFFERS in its KEXINIT, so this is a genuine offering, not
# a mock — ssh-weak-algorithms.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A
RUN printf 'HostKeyAlgorithms +ssh-rsa\nKexAlgorithms +diffie-hellman-group1-sha1\nPubkeyAcceptedAlgorithms +ssh-rsa\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
