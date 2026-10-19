#!/usr/bin/env bash
# Requires an existing local linux/amd64 image containing CSP 5.0.13003.
# Only disposable test keys are generated; no existing key volumes are mounted.
set -euo pipefail
if [[ $# != 2 && ( $# != 3 || $3 != --no-password ) ]]; then
  echo 'Usage: generate-csp-test-fixture.sh <local-csp-image> <new-output-directory> [--no-password]' >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
gamma="$root/tools/gost-engine/docker/dev_pkcs12/cryptopro/test_gamma/db1"
[[ -f "$gamma/kis_1" ]] || { echo 'Build/fetch pinned gost-engine first.' >&2; exit 1; }
docker image inspect "$1" >/dev/null
mkdir -m 700 "$2"
output="$(cd "$2" && pwd)"
test_password=123456
[[ "${3:-}" != --no-password ]] || test_password=''
docker run --rm --pull never --platform linux/amd64 --network none --entrypoint /bin/sh \
  -e "GOST_CSP_TEST_PASSWORD=$test_password" \
  --tmpfs /var/opt/cprocsp/keys --tmpfs /var/opt/cprocsp/users \
  -v "$output:/out" -v "$gamma:/test-gamma:ro" \
  -v "$root/scripts/csp-test-container.sh:/generate.sh:ro" "$1" /generate.sh \
  > "$output/generation.log" 2>&1
printf 'Disposable test fixtures created in %s.\n' "$output"
