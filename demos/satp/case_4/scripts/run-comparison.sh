#!/usr/bin/env bash
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case_dir="$(cd "$script_dir/.." && pwd)"
comparison_id="${1:-$(date +%Y%m%d_%H%M%S)}"
case "$comparison_id" in
  ""|*[!A-Za-z0-9._-]*) echo "invalid comparison id: $comparison_id" >&2; exit 2 ;;
esac
evidence_root="${CASE4_EVIDENCE_ROOT:-/opt/hyperledger-cacti/run-evidence/satp-case-4}"
comparison_root="$evidence_root/comparisons/$comparison_id"
runner="$script_dir/run-scenario.sh"
analyzer="$script_dir/analyze-evidence.py"
mkdir -p "$comparison_root/logs"
printf 'repetition\tscenario\texit_code\tevidence_directory\tmeasurement_json\n' >"$comparison_root/run-index.tsv"

orders=(
  "4a 4b 4c 4c-s 4d"
  "4c 4c-s 4d 4a 4b"
  "4d 4a 4b 4c 4c-s"
)

printf '%s\n' "comparison_id=$comparison_id" >"$comparison_root/methodology.txt"
printf '%s\n' "repetitions=3" >>"$comparison_root/methodology.txt"
printf '%s\n' "order_1=${orders[0]}" >>"$comparison_root/methodology.txt"
printf '%s\n' "order_2=${orders[1]}" >>"$comparison_root/methodology.txt"
printf '%s\n' "order_3=${orders[2]}" >>"$comparison_root/methodology.txt"
printf '%s\n' "proxy_image=${CASE4_PROXY_IMAGE:-cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7}" >>"$comparison_root/methodology.txt"
printf '%s\n' "proxy_digest=${CASE4_EXPECTED_PROXY_DIGEST:-sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c}" >>"$comparison_root/methodology.txt"

failures=0
for repetition_index in 0 1 2; do
  repetition=$((repetition_index + 1))
  for scenario in ${orders[$repetition_index]}; do
    log="$comparison_root/logs/r${repetition}-${scenario}.log"
    echo "comparison=$comparison_id repetition=$repetition scenario=$scenario start"
    set +e
    CASE4_BUILD=0 "$runner" "$scenario" 2>&1 | tee "$log"
    exit_code=${PIPESTATUS[0]}
    set -e
    evidence="$(sed -n 's/^evidence=//p' "$log" | tail -1)"
    measurement=""
    if [ "$exit_code" -eq 0 ] && [ -n "$evidence" ]; then
      measurement="$("$analyzer" analyze --evidence "$evidence" --scenario "$scenario" --repetition "$repetition" | tail -1)"
    else
      failures=$((failures + 1))
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$repetition" "$scenario" "$exit_code" "$evidence" "$measurement" >>"$comparison_root/run-index.tsv"
    echo "comparison=$comparison_id repetition=$repetition scenario=$scenario exit=$exit_code"
  done
done

"$analyzer" aggregate --comparison-root "$comparison_root"
find "$comparison_root" -type f ! -name SHA256SUMS -printf '%P\0' \
  | sort -z | xargs -0 -r -I{} sha256sum "$comparison_root/{}" >"$comparison_root/SHA256SUMS"
echo "comparison=$comparison_root"
echo "failures=$failures"
test "$failures" -eq 0
