# CA-signed, full chain, past validity: tls-certificate-expired only. Not
# self-signed (issuer is the lab CA) and full chain, so no other TLS rule fires.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY gen-cert.sh /gen-cert.sh
RUN sh /gen-cert.sh expired.lab.invalid 2048 ca-expired
COPY nginx.conf /etc/nginx/conf.d/default.conf
