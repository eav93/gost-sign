#!/usr/bin/env bash
set -euo pipefail
openssl_root="${OPENSSL_ROOT_DIR:-${OPENSSL_DIR:-}}"
if [[ -z "$openssl_root" ]]; then
  if [[ "$(uname -s)" == Darwin ]] && command -v brew >/dev/null; then
    openssl_root="$(brew --prefix openssl@3)"
  else
    echo 'Set OPENSSL_ROOT_DIR to the same OpenSSL >=3.4 installation used to build the provider.' >&2
    exit 1
  fi
fi
exec env OPENSSL_DIR="$openssl_root" cargo "$@"
