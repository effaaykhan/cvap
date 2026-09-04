# A real FTP server. vsftpd's 220 banner is its own version statement; plaintext
# -> plaintext-ftp. secure_chroot_dir must exist at RUNTIME — /var/run is a fresh
# tmpfs at container start, wiping any build-time mkdir — so the CMD makes it.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends vsftpd \
    && rm -rf /var/lib/apt/lists/*
RUN printf 'listen=YES\nanonymous_enable=YES\nseccomp_sandbox=NO\npasv_enable=NO\nsecure_chroot_dir=/var/run/vsftpd/empty\nftpd_banner=vsftpd (CVAP lab)\n' > /etc/vsftpd.conf
EXPOSE 21
CMD ["sh","-c","mkdir -p /var/run/vsftpd/empty && exec /usr/sbin/vsftpd /etc/vsftpd.conf"]
