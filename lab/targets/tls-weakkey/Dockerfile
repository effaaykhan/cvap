# CA-signed, full chain, 1024-bit RSA leaf: tls-weak-key only.
FROM nginx:1.14-alpine
RUN apk add --no-cache openssl
COPY gen-cert.sh /gen-cert.sh
RUN sh /gen-cert.sh weakkey.lab.invalid 1024 ca-full
COPY nginx.conf /etc/nginx/conf.d/default.conf
