#!/usr/bin/env bash
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  4a) profile=classical; expected_group=X25519; expected_log_group=X25519; expected_wire_group=29; expected_client_verify=NONE ;;
  4b) profile=classical; expected_group=X25519; expected_log_group=X25519; expected_wire_group=29; expected_client_verify=SUCCESS ;;
  4c) profile=classical; expected_group=X25519MLKEM768; expected_log_group=0x11ec; expected_wire_group=4588; expected_client_verify=SUCCESS ;;
  4c-s) profile=classical; expected_group=MLKEM768; expected_log_group=0x0201; expected_wire_group=513; expected_client_verify=SUCCESS ;;
  4d) profile=mldsa44; expected_group=X25519MLKEM768; expected_log_group=0x11ec; expected_wire_group=4588; expected_client_verify=SUCCESS ;;
  *) echo "usage: $0 4a|4b|4c|4c-s|4d" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case_dir="$(cd "$script_dir/.." && pwd)"
repo="$(cd "$case_dir/../../.." && pwd)"
runtime_root="${CASE4_RUNTIME_ROOT:-/opt/hyperledger-cacti/runtime/satp-case-4}"
evidence_root="${CASE4_EVIDENCE_ROOT:-/opt/hyperledger-cacti/run-evidence/satp-case-4}"
proxy_image="${CASE4_PROXY_IMAGE:-cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7}"
expected_proxy_digest="${CASE4_EXPECTED_PROXY_DIGEST:-sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c}"
deb_repo_url="${CASE4_DEB_REPO_URL:-http://10.10.20.155/nginx/linux/debian/trixie/amd64/nginx-debs}"
compose_override="${CASE4_COMPOSE_OVERRIDE:-/opt/hyperledger-cacti/config/satp-case-1-privileged.compose.yaml}"
pki_root="$runtime_root/pki/$profile"
stamp="$(date +%Y%m%d_%H%M%S)"
evidence="$evidence_root/$scenario/$stamp"

test "$(id -un)" = ots
test -f "$compose_override"
mkdir -p "$evidence"

export PATH=/opt/hyperledger-cacti/bin:$PATH
export CASE4_DEB_REPO_URL="$deb_repo_url"
export CASE4_SCENARIO="$scenario"
export CASE4_PKI_ROOT="$pki_root"
compose=(docker compose -f "$case_dir/docker-compose.yaml" -f "$compose_override")
capture_pid=

stop_port_processes() {
  for port in 8545 8546; do
    pids="$(lsof -ti:"$port" 2>/dev/null || true)"
    if [ -n "$pids" ]; then kill $pids; fi
  done
}

cleanup() {
  set +e
  if [ -n "${capture_pid:-}" ] && kill -0 "$capture_pid" 2>/dev/null; then
    kill -INT "$capture_pid"
    wait "$capture_pid"
  fi
  "${compose[@]}" down -v >>"$evidence/cleanup.log" 2>&1
  stop_port_processes
  for generated in "$case_dir/satp-hermes-gateway" "$case_dir/audits" "$case_dir/outputs"; do
    if [ -e "$generated" ]; then sudo -n chown -R ots:ots "$generated"; fi
  done
  sleep 2
}
trap cleanup EXIT

if [ "${CASE4_BUILD:-1}" = 1 ]; then
  docker build --pull=false --build-arg "DEB_REPO_URL=$deb_repo_url" \
    -t "$proxy_image" "$case_dir/nginx" >"$evidence/proxy-build.log" 2>&1
fi

actual_proxy_digest="$(docker image inspect "$proxy_image" --format '{{.Id}}')"
test "$actual_proxy_digest" = "$expected_proxy_digest"

if [ ! -f "$pki_root/proxy-1/server.crt" ]; then
  CASE4_PROXY_IMAGE="$proxy_image" CASE4_RUNTIME_ROOT="$runtime_root" \
    "$case_dir/pki/generate-pki.sh" "$profile" >"$evidence/pki-generation.log" 2>&1
fi

"${compose[@]}" config -q
"${compose[@]}" down -v >"$evidence/pre-cleanup.log" 2>&1 || true
stop_port_processes
sleep 1

(
  cd "$repo/utils/test-ledgers"
  npx hardhat node --hostname 0.0.0.0 --port 8545
) >"$evidence/ledger-8545.log" 2>&1 &
(
  cd "$repo/utils/test-ledgers"
  npx hardhat node --hostname 0.0.0.0 --port 8546
) >"$evidence/ledger-8546.log" 2>&1 &

for port in 8545 8546; do
  ready=0
  for attempt in $(seq 1 30); do
    if curl -fsS -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
      "http://127.0.0.1:$port" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  test "$ready" = 1
done

"${compose[@]}" create --no-build >"$evidence/compose-create.log" 2>&1
network_name="$("${compose[@]}" config --format json | jq -r '.networks.default.name')"
network_id="$(docker network inspect "$network_name" --format '{{.Id}}')"
capture_interface="br-${network_id:0:12}"
test -d "/sys/class/net/$capture_interface"
printf '%s\n' "$capture_interface" >"$evidence/capture-interface.txt"

tshark -i "$capture_interface" -f 'tcp port 3443' -w "$evidence/proxy-tls.pcapng" \
  >"$evidence/tshark-capture.log" 2>&1 &
capture_pid=$!
sleep 1

"${compose[@]}" up -d --no-build >"$evidence/compose-up.log" 2>&1
sleep 10
"${compose[@]}" ps >"$evidence/compose-ps.log"

(cd "$case_dir"; python3 satp-evm-get-integrations.py) >"$evidence/integrations.log"
(cd "$repo/utils/test-ledgers"; node scripts/SATPTokenContract.js) >"$evidence/deploy.log"
sleep 6
(cd "$repo/utils/test-ledgers"; node scripts/SATPTokenContract-CheckBalances.js) >"$evidence/balances-before.log"
sleep 3
satp_start_ns="$(date +%s%N)"
(cd "$case_dir"; python3 satp-transact.py) >"$evidence/session_output.json"
satp_end_ns="$(date +%s%N)"
python3 - "$satp_start_ns" "$satp_end_ns" "$evidence/satp-timing.json" <<'PYTIMING'
import json, sys
start_ns, end_ns = int(sys.argv[1]), int(sys.argv[2])
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(
        {
            "start_epoch_ns": start_ns,
            "end_epoch_ns": end_ns,
            "duration_ms": (end_ns - start_ns) / 1_000_000,
            "definition": "wall-clock duration of satp-transact.py",
        },
        handle,
        indent=2,
    )
    handle.write("\n")
PYTIMING
session_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessionID"])' "$evidence/session_output.json")"
(cd "$case_dir"; python3 satp-evm-check-status.py "$session_id") >"$evidence/status.log"
(cd "$case_dir"; python3 satp-evm-perform-audit.py) >"$evidence/audit.log"
(cd "$repo/utils/test-ledgers"; node scripts/SATPTokenContract-CheckBalances.js) >"$evidence/balances-after.log"

gateway2_id="$("${compose[@]}" ps -q satp-hermes-gateway-2)"
test -n "$gateway2_id"
docker exec "$gateway2_id" node -e '
fetch("http://satp-tls-proxy-2:8080/case4-reverse-probe")
  .then(async (response) => {
    console.log("status=" + response.status);
    console.log(await response.text());
    if (response.status !== 404) process.exit(1);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
' >"$evidence/reverse-path-probe.log" 2>&1

python3 - "$evidence/session_output.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
status = result["statusResponse"]
assert status["status"] == "DONE", status
assert status["substatus"] == "COMPLETED", status
assert status["stage"] == "SATP_STAGE_3", status
assert status["step"] == "transfer-complete-message", status
PY
grep -q '8545 - User Balance: 100' "$evidence/balances-before.log"
grep -q '8546 - User Balance: 0' "$evidence/balances-before.log"
grep -q '8545 - User Balance: 0' "$evidence/balances-after.log"
grep -q '8546 - User Balance: 100' "$evidence/balances-after.log"
test "$(grep -c 'Bridge Contract Balance: 0' "$evidence/balances-after.log")" = 2

"${compose[@]}" logs satp-tls-proxy-1 satp-tls-proxy-2 >"$evidence/proxy.log" 2>&1
grep -q 'tls=TLSv1.3' "$evidence/proxy.log"
grep -q "group=$expected_log_group" "$evidence/proxy.log"
grep -q "client_verify=$expected_client_verify" "$evidence/proxy.log"
grep -q 'status=404' "$evidence/reverse-path-probe.log"
grep -q "satp-tls-proxy-1-1.*tls=TLSv1.3.*group=$expected_log_group.*client_verify=$expected_client_verify" "$evidence/proxy.log"
grep -q "satp-tls-proxy-2-1.*tls=TLSv1.3.*group=$expected_log_group.*client_verify=$expected_client_verify" "$evidence/proxy.log"

kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=

capinfos "$evidence/proxy-tls.pcapng" >"$evidence/capinfos.txt"
tshark -r "$evidence/proxy-tls.pcapng" -Y 'tls.handshake.type == 2' \
  -T fields -E header=y -E separator=, \
  -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tls.handshake.extensions_key_share_group \
  >"$evidence/server-hello-groups.csv" 2>"$evidence/tshark-analysis.log"
observed_wire_groups="$(tail -n +2 "$evidence/server-hello-groups.csv" | cut -d, -f6 | sed '/^$/d' | sort -u)"
test "$observed_wire_groups" = "$expected_wire_group"
http_frames="$(tshark -r "$evidence/proxy-tls.pcapng" -Y http -T fields -e frame.number 2>/dev/null | wc -l)"
printf '%s\n' "$http_frames" >"$evidence/cleartext-http-frame-count.txt"
test "$http_frames" = 0
stage_markers="$(grep -a -o '/stage-[0-3]' "$evidence/proxy-tls.pcapng" 2>/dev/null | wc -l || true)"
printf '%s\n' "$stage_markers" >"$evidence/cleartext-stage-marker-count.txt"
test "$stage_markers" = 0

docker image inspect "$proxy_image" >"$evidence/proxy-image-inspect.json"
docker run --rm --network none "$proxy_image" openssl version -a >"$evidence/openssl-version.txt"
docker run --rm --network none "$proxy_image" openssl list -providers >"$evidence/openssl-providers.txt"
docker run --rm --network none "$proxy_image" openssl list -tls-groups >"$evidence/openssl-tls-groups.txt"
docker run --rm --network none "$proxy_image" nginx -V >"$evidence/nginx-version.txt" 2>&1
cp "$pki_root/ca/ca.crt" "$evidence/ca.crt"
for proxy in 1 2; do
  cp "$pki_root/proxy-$proxy/server.crt" "$evidence/proxy-$proxy-server.crt"
  cp "$pki_root/proxy-$proxy/client.crt" "$evidence/proxy-$proxy-client.crt"
done
find "$case_dir/audits" -maxdepth 1 -type f -mmin -5 -exec cp {} "$evidence/" \; 2>/dev/null || true

cleanup
trap - EXIT
printf '%s\n' '---PORTS---' >"$evidence/post-cleanup.txt"
ss -ltn | grep -E ':(3010|3011|3110|3111|4010|4110|8545|8546)[[:space:]]' >>"$evidence/post-cleanup.txt" || true
test "$(wc -l <"$evidence/post-cleanup.txt")" = 1
printf '%s\n' '---SERVICES---' >>"$evidence/post-cleanup.txt"
for service in docker gitea grafana-server mysql postgresql; do
  printf '%s=' "$service" >>"$evidence/post-cleanup.txt"
  systemctl is-active "$service" >>"$evidence/post-cleanup.txt"
done
git -C "$repo" status --short >"$evidence/source-status.txt"
find "$evidence" -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\0' \
  | sort -z | xargs -0 -r -I{} sha256sum "$evidence/{}" >"$evidence/SHA256SUMS"

echo "scenario=$scenario"
echo "session=$session_id"
echo "group=$expected_group"
echo "client_verify=$expected_client_verify"
echo "evidence=$evidence"
