# CA-signed leaf presented ALONE: tls-missing-chain (self_signed false, chain 1).
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY gen-cert.sh /gen-cert.sh
RUN sh /gen-cert.sh nochain.lab.invalid 2048 ca-leaf
COPY nginx.conf /etc/nginx/conf.d/default.conf
