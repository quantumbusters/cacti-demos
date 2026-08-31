#!/usr/bin/env bash
set -euo pipefail

set_id="${1:-$(date +%Y%m%d_%H%M%S)}"
case "$set_id" in
  ""|*[!A-Za-z0-9._-]*) echo "invalid decryptable set id: $set_id" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case_dir="$(cd "$script_dir/.." && pwd)"
evidence_root="${CASE4_EVIDENCE_ROOT:-/opt/hyperledger-cacti/run-evidence/satp-case-4}"
runtime_root="${CASE4_RUNTIME_ROOT:-/opt/hyperledger-cacti/runtime/satp-case-4}"
bundle="$evidence_root/decryptable/$set_id"
keylog_image="${CASE4_KEYLOG_IMAGE:-cacti-satp-tls-proxy-keylog:nginx-1.26.3-openssl-3.5.7}"
keylog_digest="${CASE4_KEYLOG_IMAGE_DIGEST:-sha256:d7c5e34a5690225cd23c30e712bcfac57cebc0272bc5a4c4d81f6a6a74522b38}"

test "$(id -un)" = ots
test "$(docker image inspect "$keylog_image" --format '{{.Id}}')" = "$keylog_digest"
install -d -m 0755 "$bundle"
install -d -m 0755 "$bundle/logs"
printf 'scenario\tsession\tgroup\tevidence_directory\tcapture\tkeylog\n' >"$bundle/index.tsv"

cat >"$bundle/README.txt" <<'EOF'
WIRESHARK DECRYPTION BUNDLE

Each scenario directory contains:
  proxy-tls.pcapng  - the protected proxy-to-proxy capture
  wireshark.keys    - NSS-format TLS session secrets for that capture
  decrypted-http-requests.csv - independent TShark decryption proof

In Wireshark:
1. Open the scenario's proxy-tls.pcapng.
2. Open Edit > Preferences > Protocols > TLS.
3. Set "(Pre)-Master-Secret log filename" to that scenario's wireshark.keys.
4. Apply the display filter: http.request
5. The SATP /stage-0 through /stage-3 requests should be visible.

The capture and matching key log are a pair. Keep them together when sharing
this disposable demo evidence with project participants. Do not use the
analysis image or key logging on production traffic.
EOF
chmod 0644 "$bundle/README.txt"

for scenario in 4a 4b 4c 4c-s 4d; do
  scenario_bundle="$bundle/$scenario"
  install -d -m 0755 "$scenario_bundle"
  log="$bundle/logs/$scenario.log"
  keylog_root="$runtime_root/keylogs/$set_id-$scenario"
  echo "decryptable_set=$set_id scenario=$scenario start"
  CASE4_BUILD=0   CASE4_PROXY_IMAGE="$keylog_image"   CASE4_EXPECTED_PROXY_DIGEST="$keylog_digest"   CASE4_KEYLOG_ROOT="$keylog_root"     "$script_dir/run-scenario.sh" "$scenario" 2>&1 | tee "$log"
  evidence="$(sed -n 's/^evidence=//p' "$log" | tail -1)"
  session="$(sed -n 's/^session=//p' "$log" | tail -1)"
  group="$(sed -n 's/^group=//p' "$log" | tail -1)"
  test -n "$evidence"
  test -s "$evidence/proxy-tls.pcapng"
  test -s "$evidence/wireshark.keys"
  test -s "$evidence/decrypted-http-requests.csv"
  install -m 0644 "$evidence/proxy-tls.pcapng" "$scenario_bundle/proxy-tls.pcapng"
  install -m 0644 "$evidence/wireshark.keys" "$scenario_bundle/wireshark.keys"
  install -m 0644 "$evidence/decrypted-http-requests.csv" "$scenario_bundle/decrypted-http-requests.csv"
  install -m 0644 "$evidence/DECRYPTION-NOTE.txt" "$scenario_bundle/DECRYPTION-NOTE.txt"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n'     "$scenario" "$session" "$group" "$evidence"     "$scenario_bundle/proxy-tls.pcapng" "$scenario_bundle/wireshark.keys"     >>"$bundle/index.tsv"
  tshark -o "tls.keylog_file:$scenario_bundle/wireshark.keys"     -r "$scenario_bundle/proxy-tls.pcapng" -Y 'http.request'     -T fields -e http.request.uri 2>/dev/null     | grep -q '/stage-3/'
  echo "decryptable_set=$set_id scenario=$scenario PASS"
done

chmod 0644 "$bundle/index.tsv" "$bundle/logs"/*.log
find "$bundle" -type f ! -name SHA256SUMS -printf '%P\0'   | sort -z | xargs -0 -r -I{} sha256sum "$bundle/{}" >"$bundle/SHA256SUMS"
chmod 0644 "$bundle/SHA256SUMS"
echo "decryptable_bundle=$bundle"
