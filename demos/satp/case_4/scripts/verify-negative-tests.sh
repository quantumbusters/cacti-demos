#!/usr/bin/env bash
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  4b) profile=classical; group=X25519 ;;
  4d) profile=mldsa44; group=X25519MLKEM768 ;;
  *) echo "usage: $0 4b|4d" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case_dir="$(cd "$script_dir/.." && pwd)"
runtime_root="${CASE4_RUNTIME_ROOT:-/opt/hyperledger-cacti/runtime/satp-case-4}"
evidence_root="${CASE4_EVIDENCE_ROOT:-/opt/hyperledger-cacti/run-evidence/satp-case-4}"
proxy_image="${CASE4_PROXY_IMAGE:-cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7}"
expected_proxy_digest="${CASE4_EXPECTED_PROXY_DIGEST:-sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c}"
deb_repo_url="${CASE4_DEB_REPO_URL:-http://10.10.20.155/nginx/linux/debian/trixie/amd64/nginx-debs}"
compose_override="${CASE4_COMPOSE_OVERRIDE:-/opt/hyperledger-cacti/config/satp-case-1-privileged.compose.yaml}"
pki_root="$runtime_root/pki/$profile"
negative_root="$runtime_root/negative/$profile"
stamp="$(date +%Y%m%d_%H%M%S)"
evidence="$evidence_root/$scenario/negative-$stamp"

test "$(id -un)" = ots
test -f "$pki_root/proxy-1/client.crt"
mkdir -p "$evidence"

export CASE4_DEB_REPO_URL="$deb_repo_url"
export CASE4_SCENARIO="$scenario"
export CASE4_PKI_ROOT="$pki_root"
compose=(docker compose -f "$case_dir/docker-compose.yaml" -f "$compose_override")

cleanup() {
  set +e
  "${compose[@]}" down -v >>"$evidence/cleanup.log" 2>&1
}
trap cleanup EXIT

actual_proxy_digest="$(docker image inspect "$proxy_image" --format '{{.Id}}')"
test "$actual_proxy_digest" = "$expected_proxy_digest"

case "$negative_root" in
  /opt/hyperledger-cacti/runtime/satp-case-4/negative/*) ;;
  *) echo "unexpected negative-test path: $negative_root" >&2; exit 3 ;;
esac
rm -rf "$negative_root"
install -d -m 0700 "$negative_root"
uid="$(id -u)"
gid="$(id -g)"
docker run --rm -i --network none --user "$uid:$gid" \
  -e PROFILE="$profile" -v "$negative_root:/rogue" "$proxy_image" /bin/sh <<'CONTAINER'
set -e
umask 077
if [ "$PROFILE" = classical ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /rogue/ca.key
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /rogue/client.key
else
  openssl genpkey -algorithm ML-DSA-44 -out /rogue/ca.key
  openssl genpkey -algorithm ML-DSA-44 -out /rogue/client.key
fi
openssl req -new -x509 -key /rogue/ca.key -subj "/CN=Untrusted Case 4 CA" -days 2 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out /rogue/ca.crt
openssl req -new -key /rogue/client.key -subj "/CN=untrusted-client.case4.test" \
  -out /rogue/client.csr
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' \
  >/rogue/client.ext
openssl x509 -req -in /rogue/client.csr -CA /rogue/ca.crt -CAkey /rogue/ca.key \
  -CAcreateserial -days 2 -extfile /rogue/client.ext -out /rogue/client.crt
chmod 600 /rogue/*.key
chmod 644 /rogue/*.crt
CONTAINER
find "$negative_root" -type f \( -name '*.csr' -o -name '*.ext' -o -name '*.srl' \) -delete

"${compose[@]}" down -v >/dev/null 2>&1 || true
"${compose[@]}" up -d --no-deps satp-tls-proxy-1 satp-tls-proxy-2 \
  >"$evidence/compose-up.log" 2>&1
sleep 3
proxy1_id="$("${compose[@]}" ps -q satp-tls-proxy-1)"
test -n "$proxy1_id"
network="$(docker inspect "$proxy1_id" | jq -r '.[0].NetworkSettings.Networks | keys[0]')"

set +e
printf 'GET / HTTP/1.1\r\nHost: proxy-2.case4.test\r\nConnection: close\r\n\r\n' \
  | docker exec -i "$proxy1_id" openssl s_client -quiet \
      -connect satp-tls-proxy-2:3443 -servername proxy-2.case4.test \
      -verify_return_error -CAfile /run/case4/tls/ca.crt -groups "$group" \
      >"$evidence/missing-client-cert.log" 2>&1
missing_rc=$?
set -e
grep -q '400 Bad Request' "$evidence/missing-client-cert.log"
grep -q 'No required SSL certificate was sent' "$evidence/missing-client-cert.log"

set +e
printf 'GET / HTTP/1.1\r\nHost: proxy-2.case4.test\r\nConnection: close\r\n\r\n' \
  | docker run --rm -i --network "$network" \
      -v "$negative_root:/rogue:ro" -v "$pki_root/proxy-1:/trusted:ro" \
      "$proxy_image" openssl s_client -quiet -connect satp-tls-proxy-2:3443 \
        -servername proxy-2.case4.test -verify_return_error \
        -CAfile /trusted/ca.crt -cert /rogue/client.crt -key /rogue/client.key \
        -groups "$group" >"$evidence/untrusted-client-ca.log" 2>&1
untrusted_rc=$?
set -e
grep -q '400 Bad Request' "$evidence/untrusted-client-ca.log"
grep -qi -E 'SSL certificate error|certificate verify failed' \
  "$evidence/untrusted-client-ca.log"

set +e
docker run --rm --network "$network" -v "$pki_root/proxy-1:/valid:ro" \
  "$proxy_image" openssl s_client -connect satp-tls-proxy-2:3443 \
    -servername proxy-2.case4.test -verify_hostname wrong.case4.test \
    -verify_return_error -CAfile /valid/ca.crt \
    -cert /valid/client.crt -key /valid/client.key -groups "$group" \
    </dev/null >"$evidence/wrong-server-san.log" 2>&1
san_rc=$?
set -e
test "$san_rc" -ne 0
grep -qi 'hostname mismatch' "$evidence/wrong-server-san.log"

printf '%s\n' 'ssl_verify_client on;' \
  'ssl_conf_command Groups NOT_A_TLS_GROUP;' \
  >"$evidence/invalid-group-ingress.conf"
set +e
docker run --rm --network none \
  -v "$case_dir/nginx/proxy-1.conf:/etc/nginx/conf.d/proxy.conf:ro" \
  -v "$evidence/invalid-group-ingress.conf:/etc/nginx/scenario/ingress.conf:ro" \
  -v "$case_dir/nginx/scenarios/$scenario/egress.conf:/etc/nginx/scenario/egress.conf:ro" \
  -v "$pki_root/proxy-1:/run/case4/tls:ro" \
  "$proxy_image" nginx -t >"$evidence/invalid-group.log" 2>&1
group_rc=$?
set -e
test "$group_rc" -ne 0
grep -qi -E 'bad value|invalid|unknown' "$evidence/invalid-group.log"

"${compose[@]}" logs satp-tls-proxy-1 satp-tls-proxy-2 >"$evidence/proxy.log" 2>&1
grep -q 'client sent no required SSL certificate' "$evidence/proxy.log"
grep -q 'client SSL certificate verify error' "$evidence/proxy.log"
cleanup
trap - EXIT

{
  echo "missing_client_command_exit=$missing_rc"
  echo "untrusted_client_command_exit=$untrusted_rc"
  echo "wrong_san_command_exit=$san_rc"
  echo "invalid_group_command_exit=$group_rc"
  echo "result=PASS"
} >"$evidence/result.txt"
find "$evidence" -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\0' \
  | sort -z | xargs -0 -r -I{} sha256sum "$evidence/{}" >"$evidence/SHA256SUMS"

echo "scenario=$scenario"
echo "negative_tests=PASS"
echo "evidence=$evidence"
