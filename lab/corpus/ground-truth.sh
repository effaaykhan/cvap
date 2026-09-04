#!/bin/sh
# Capture what each lab target says about ITSELF, by execing into the container
# and asking the software — never by scanning it.
#
# ============================================================================
# This is the independent-labelling boundary. The golden corpus is authored from
# THIS output; the scanner's observations are diffed AGAINST the corpus. The two
# sources never cross, so a passing corpus-check cannot be the scanner agreeing
# with itself.
# ============================================================================
#
# Emits one JSON object per target on stdout (JSONL): the container name, and the
# facts read from inside it — nginx/openssh/vsftpd versions, the certificate's
# own subject/issuer/dates/key-size as openssl reports them, the sshd's offered
# algorithms as sshd itself prints them. A human re-runs this to re-verify the
# committed labels; CI runs it to assert they have not drifted.
#
# Usage: lab/corpus/ground-truth.sh   (the lab must be up)
set -eu

emit() { printf '%s\n' "$1"; }

# jq-free JSON string escaper for the values we capture (versions, DNs).
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }

# --- nginx version, from the binary itself ---
nginx_ver() { docker exec "$1" nginx -v 2>&1 | sed -n 's#.*nginx/##p' | head -1; }

# --- a certificate's own account of itself ---
cert_field() { # container certpath field
  docker exec "$1" openssl x509 -in "$2" -noout "$3" 2>/dev/null | sed 's/^[^=]*=//' | head -1
}
cert_selfsigned() { # subject == issuer ?
  s=$(docker exec "$1" openssl x509 -in "$2" -noout -subject 2>/dev/null | sed 's/^subject=//')
  i=$(docker exec "$1" openssl x509 -in "$2" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
  [ "$s" = "$i" ] && echo true || echo false
}
cert_bits() { docker exec "$1" openssl x509 -in "$2" -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1; }
cert_expired() { # enddate before now?
  end=$(docker exec "$1" openssl x509 -in "$2" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
  if docker exec "$1" openssl x509 -in "$2" -noout -checkend 0 >/dev/null 2>&1; then echo false; else echo true; fi
}

tls_cert() { # name container certpath  -> JSON fragment
  n="$1"; c="$2"; p="$3"
  chain=$(docker exec "$c" grep -c "BEGIN CERTIFICATE" "$p" 2>/dev/null || echo 0)
  emit "{\"target\":\"$n\",\"kind\":\"tls\",\"cert_path\":\"$(esc "$p")\",\"key_bits\":\"$(cert_bits "$c" "$p")\",\"served_chain_len\":${chain:-0},\"self_signed\":$(cert_selfsigned "$c" "$p"),\"expired\":$(cert_expired "$c" "$p"),\"subject\":\"$(esc "$(cert_field "$c" "$p" -subject)")\",\"issuer\":\"$(esc "$(cert_field "$c" "$p" -issuer)")\"}"
}

# nginx plaintext targets
for t in a1:10.10.0.11 a2:10.10.0.12 a3:10.10.0.13 a6:10.10.0.16; do
  name=${t%%:*}; ip=${t##*:}
  c="cvap-lab-target-${name}-1"
  emit "{\"target\":\"$name\",\"ip\":\"$ip\",\"kind\":\"http\",\"nginx\":\"$(esc "$(nginx_ver "$c")")\"}"
done

# TLS targets — the certificate describes itself
tls_cert tls-expired    cvap-lab-target-a-tls-expired-1    /certs/serve.crt
tls_cert tls-nochain    cvap-lab-target-a-tls-nochain-1    /certs/serve.crt
tls_cert tls-weakkey    cvap-lab-target-a-tls-weakkey-1    /certs/serve.crt
tls_cert tls-legacy     cvap-lab-target-a-tls-legacy-1     /certs/serve.crt
tls_cert tls-weakcipher cvap-lab-target-a-tls-weakcipher-1 /certs/serve.crt
tls_cert a5             cvap-lab-target-a5-1               /etc/ssl/certs/lab.crt

# The two nginx:1.14 targets: their configured protocol/cipher, from their own conf
emit "{\"target\":\"tls-legacy\",\"kind\":\"tls_conf\",\"ssl_protocols\":\"$(esc "$(docker exec cvap-lab-target-a-tls-legacy-1 sed -n 's/.*ssl_protocols *//p' /etc/nginx/conf.d/default.conf | tr -d ';' | head -1)")\"}"
emit "{\"target\":\"tls-weakcipher\",\"kind\":\"tls_conf\",\"ssl_ciphers\":\"$(esc "$(docker exec cvap-lab-target-a-tls-weakcipher-1 sed -n 's/.*ssl_ciphers *//p' /etc/nginx/conf.d/default.conf | tr -d '\";' | head -1)")\"}"

# telnet, ftp
emit "{\"target\":\"telnet\",\"ip\":\"10.10.0.23\",\"kind\":\"telnet\",\"impl\":\"busybox-telnetd\"}"
emit "{\"target\":\"ftp\",\"ip\":\"10.10.0.24\",\"kind\":\"ftp\",\"vsftpd\":\"$(esc "$(docker exec cvap-lab-target-a-ftp-1 sh -c 'vsftpd -v 0>&1 2>&1 || dpkg-query -W -f=\${Version} vsftpd' 2>/dev/null)")\"}"

# ssh targets — sshd's own version and the algorithms it is configured to offer
ssh_algos() { # container -> "hostkeyalgs|kexalgs" as sshd resolves them
  hk=$(docker exec "$1" sshd -T 2>/dev/null | sed -n 's/^hostkeyalgorithms //p' | head -1)
  kx=$(docker exec "$1" sshd -T 2>/dev/null | sed -n 's/^kexalgorithms //p' | head -1)
  printf '%s|%s' "$hk" "$kx"
}
for t in "a4:cvap-lab-target-a4-1:10.10.0.14" "ssh-weak:cvap-lab-target-a-ssh-weak-1:10.10.0.26" "b-ssh:cvap-lab-target-b-ssh-1:10.20.0.12"; do
  name=$(echo "$t" | cut -d: -f1); c=$(echo "$t" | cut -d: -f2); ip=$(echo "$t" | cut -d: -f3)
  ver=$(docker exec "$c" sh -c 'sshd -V 2>&1 || ssh -V 2>&1' 2>/dev/null | head -1 || true)
  algos=$(ssh_algos "$c" 2>/dev/null || echo "|")
  emit "{\"target\":\"$name\",\"ip\":\"$ip\",\"kind\":\"ssh\",\"version\":\"$(esc "$ver")\",\"host_key_algorithms\":\"$(esc "${algos%%|*}")\",\"kex_algorithms\":\"$(esc "${algos##*|}")\"}"
done
