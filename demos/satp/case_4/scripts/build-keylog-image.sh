#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
keylog_dir="$(cd "$script_dir/../nginx/keylog" && pwd)"
base_image="${CASE4_BASE_PROXY_IMAGE:-cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7}"
base_digest="${CASE4_BASE_PROXY_DIGEST:-sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c}"
output_image="${CASE4_KEYLOG_IMAGE:-cacti-satp-tls-proxy-keylog:nginx-1.26.3-openssl-3.5.7}"
expected_output_digest="${CASE4_KEYLOG_IMAGE_DIGEST:-sha256:d7c5e34a5690225cd23c30e712bcfac57cebc0272bc5a4c4d81f6a6a74522b38}"
shared_object="$keylog_dir/libsslkeylog.so"

test "$(docker image inspect "$base_image" --format '{{.Id}}')" = "$base_digest"
cleanup() {
  rm -f "$shared_object"
}
trap cleanup EXIT

gcc -shared -fPIC -O2 -Wall -Wextra -Werror \
  -Wl,--version-script="$keylog_dir/openssl-symbols.map" \
  -o "$shared_object" "$keylog_dir/sslkeylog.c" -ldl
chmod 0555 "$shared_object"
readelf -Ws "$shared_object" | grep -q 'SSL_CTX_new$'
readelf -Ws "$shared_object" | grep -q 'SSL_CTX_new_ex$'
readelf -Ws "$shared_object" | grep -q 'SSL_CTX_set_keylog_callback@@OPENSSL_3.0.0'

docker build --pull=false --provenance=false \
  --build-arg "BASE_IMAGE=$base_image@$base_digest" \
  -t "$output_image" "$keylog_dir"
actual_output_digest="$(docker image inspect "$output_image" --format '{{.Id}}')"
test "$actual_output_digest" = "$expected_output_digest"
printf '%s\n' "$actual_output_digest"
