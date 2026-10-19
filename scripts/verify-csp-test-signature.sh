#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: verify-csp-test-signature.sh <local-csp-image> <fixture-directory>' >&2
  exit 2
fi
output="$(cd "$2" && pwd)"
[[ -f "$output/rust-signed.p7s" && -f "$output/rust-signed.bin" ]]
docker run --rm --pull never --platform linux/amd64 --network none \
  --entrypoint /opt/cprocsp/bin/amd64/csptest \
  --tmpfs /var/opt/cprocsp/keys --tmpfs /var/opt/cprocsp/users \
  -v "$output/rust-signed.p7s:/test.p7s:ro" -v "$output/rust-signed.bin:/test.bin:ro" \
  "$1" -sfsign -verify -in /test.bin -signature /test.p7s -detached
