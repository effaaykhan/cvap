# nginx 1.14 (OpenSSL 1.1) offering only TLS 1.0: tls-legacy-version-negotiated.
# CA-signed full chain, valid — so only the version rule fires.
FROM nginx:1.14-alpine
RUN apk add --no-cache openssl
COPY gen-cert.sh /gen-cert.sh
RUN sh /gen-cert.sh legacy.lab.invalid 2048 ca-full
COPY nginx.conf /etc/nginx/conf.d/default.conf
