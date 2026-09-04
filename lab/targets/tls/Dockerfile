# A TLS target whose certificate is worth looking at.
#
# Self-signed, 30-day lifetime, SANs, and a deliberately small key — the
# properties week 6's non-CVE rules examine. Generated at BUILD time rather
# than committed, because a committed private key is a secret in the repository
# however loudly the comment says it is fake, and the secret scanners are right
# to object.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl && \
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout /etc/ssl/private/lab.key -out /etc/ssl/certs/lab.crt \
      -days 30 -subj "/C=GB/O=CVAP Lab/CN=lab-tls.invalid" \
      -addext "subjectAltName=DNS:lab-tls.invalid,DNS:alt.lab-tls.invalid,IP:10.10.0.15"

COPY nginx.conf /etc/nginx/conf.d/default.conf
