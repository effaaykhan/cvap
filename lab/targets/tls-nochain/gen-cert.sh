#!/bin/sh
# Generate a certificate for a corpus TLS target. The MODE decides which finding
# the target reproduces; nothing here is read by our scanner, so the cert is an
# independent input. SANs are omitted deliberately — no finding rule reads them,
# and dropping them keeps this portable across openssl builds.
#
#   selfsigned  subject==issuer, chain len 1      -> tls-self-signed-non-dev
#   ca-leaf     CA-signed, leaf presented alone   -> tls-missing-chain
#   ca-full     CA-signed, full chain, valid      -> (no cert finding on its own)
#   ca-expired  CA-signed, full chain, past dates -> tls-certificate-expired
#
# CN and KEYBITS are the other knobs (1024 bits -> tls-weak-key).
set -e
CN="$1"; KEYBITS="$2"; MODE="$3"
D=/certs; mkdir -p "$D"; cd "$D"

openssl req -x509 -nodes -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 3650 -subj "/O=CVAP Lab CA/CN=CVAP Lab Root" 2>/dev/null
openssl req -nodes -newkey "rsa:${KEYBITS}" -keyout leaf.key -out leaf.csr \
  -subj "/O=CVAP Lab/CN=${CN}" 2>/dev/null

ca_sign() { # $1=startdate $2=enddate. openssl ca is the only path here that can
            # backdate, which is what an expired cert needs (x509 -days is future-only).
  mkdir -p ca/newcerts; : > ca/index.txt; echo 01 > ca/serial
  cat > ca.cnf <<CFG
[ca]
default_ca=d
[d]
dir=$D/ca
database=$D/ca/index.txt
new_certs_dir=$D/ca/newcerts
serial=$D/ca/serial
certificate=$D/ca.crt
private_key=$D/ca.key
default_md=sha256
policy=p
[p]
commonName=supplied
organizationName=optional
countryName=optional
CFG
  openssl ca -config ca.cnf -batch -in leaf.csr -out leaf.crt \
    -startdate "$1" -enddate "$2" 2>/dev/null
}

case "$MODE" in
  selfsigned)
    openssl x509 -req -in leaf.csr -signkey leaf.key -days 825 -out leaf.crt 2>/dev/null
    cp leaf.crt serve.crt ;;
  ca-leaf)
    ca_sign 20260101000000Z 20280101000000Z; cp leaf.crt serve.crt ;;
  ca-full)
    ca_sign 20260101000000Z 20280101000000Z; cat leaf.crt ca.crt > serve.crt ;;
  ca-expired)
    ca_sign 20260101000000Z 20260102000000Z; cat leaf.crt ca.crt > serve.crt ;;
  *) echo "unknown MODE $MODE" >&2; exit 2 ;;
esac
chmod 644 "$D"/serve.crt "$D"/leaf.key
