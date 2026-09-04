# nginx 1.14 offering only a CBC-SHA suite crypto/tls classes insecure:
# tls-weak-cipher-negotiated. TLS 1.2 so the version rule stays quiet.
FROM nginx:1.14-alpine
RUN apk add --no-cache openssl
COPY gen-cert.sh /gen-cert.sh
RUN sh /gen-cert.sh weakcipher.lab.invalid 2048 ca-full
COPY nginx.conf /etc/nginx/conf.d/default.conf
