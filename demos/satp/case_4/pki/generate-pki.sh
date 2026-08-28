#!/usr/bin/env bash
set -euo pipefail

profile="${1:-}"
case "$profile" in
  classical|mldsa44) ;;
  *) echo "usage: $0 classical|mldsa44" >&2; exit 2 ;;
esac

image="${CASE4_PROXY_IMAGE:-cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7}"
runtime_root="${CASE4_RUNTIME_ROOT:-/opt/hyperledger-cacti/runtime/satp-case-4}"
output_root="$runtime_root/pki/$profile"

case "$output_root" in
  /opt/hyperledger-cacti/runtime/satp-case-4/pki/*) ;;
  *) echo "refusing to replace unexpected PKI path: $output_root" >&2; exit 3 ;;
esac

rm -rf "$output_root"
install -d -m 0700 "$output_root"
uid="$(id -u)"
gid="$(id -g)"

docker run --rm -i --network none --user "$uid:$gid" \
  -e PROFILE="$profile" -v "$output_root:/pki" "$image" /bin/sh <<'CONTAINER'
set -e
umask 077

generate_key() {
  output="$1"
  if [ "$PROFILE" = classical ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$output"
  else
    openssl genpkey -algorithm ML-DSA-44 -out "$output"
  fi
}

mkdir -p /pki/ca /pki/proxy-1 /pki/proxy-2
generate_key /pki/ca/ca.key
openssl req -new -x509 -key /pki/ca/ca.key \
  -subj "/CN=SATP Case 4 $PROFILE Demo CA" -days 30 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out /pki/ca/ca.crt

for proxy in 1 2; do
  name="proxy-$proxy"
  peer_dir="/pki/$name"

  generate_key "$peer_dir/server.key"
  openssl req -new -key "$peer_dir/server.key" \
    -subj "/CN=$name.case4.test" -out "$peer_dir/server.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=DNS:$name.case4.test,DNS:satp-tls-proxy-$proxy"
  } >"$peer_dir/server.ext"
  openssl x509 -req -in "$peer_dir/server.csr" \
    -CA /pki/ca/ca.crt -CAkey /pki/ca/ca.key -CAcreateserial \
    -days 30 -extfile "$peer_dir/server.ext" -out "$peer_dir/server.crt"

  generate_key "$peer_dir/client.key"
  openssl req -new -key "$peer_dir/client.key" \
    -subj "/CN=$name-client.case4.test" -out "$peer_dir/client.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=clientAuth"
  } >"$peer_dir/client.ext"
  openssl x509 -req -in "$peer_dir/client.csr" \
    -CA /pki/ca/ca.crt -CAkey /pki/ca/ca.key -CAcreateserial \
    -days 30 -extfile "$peer_dir/client.ext" -out "$peer_dir/client.crt"

  cp /pki/ca/ca.crt "$peer_dir/ca.crt"
  openssl verify -CAfile /pki/ca/ca.crt -purpose sslserver "$peer_dir/server.crt"
  openssl verify -CAfile /pki/ca/ca.crt -purpose sslclient "$peer_dir/client.crt"
done

find /pki -type d -exec chmod 700 {} +
find /pki -type f -name '*.key' -exec chmod 600 {} +
find /pki -type f ! -name '*.key' -exec chmod 644 {} +
CONTAINER

find "$output_root" -type f \( -name '*.csr' -o -name '*.ext' -o -name '*.srl' \) -delete
echo "$output_root"
