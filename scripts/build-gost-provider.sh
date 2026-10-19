#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="$root/tools/gost-engine"
revision=509dcb467507149297673e68293be5b01d1aa4a8
openssl_root="${OPENSSL_ROOT_DIR:-${OPENSSL_DIR:-}}"
if [[ -z "$openssl_root" ]]; then
  if [[ "$(uname -s)" == Darwin ]] && command -v brew >/dev/null; then
    openssl_root="$(brew --prefix openssl@3)"
  else
    echo 'Set OPENSSL_ROOT_DIR to an OpenSSL >=3.4 development installation.' >&2
    exit 1
  fi
fi
if [[ ! -d "$source_dir" ]]; then
  git clone https://github.com/gost-engine/engine.git "$source_dir"
  git -C "$source_dir" checkout --detach "$revision"
fi
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$revision" ]]; then
  echo "Existing tools/gost-engine differs from pinned revision $revision; leaving it untouched." >&2
  exit 1
fi
git -C "$source_dir" submodule update --init --recursive
cmake -S "$source_dir" -B "$source_dir/build" \
  -DOPENSSL_ROOT_DIR="$openssl_root" -DOPENSSL_ENGINES_DIR="$source_dir/build/bin" \
  -DGOST_BUILD_ENGINE=OFF -DGOST_BUILD_PROVIDER=ON -DCMAKE_BUILD_TYPE=Release
cmake --build "$source_dir/build" --target gost_prov --config Release --parallel 4
printf '\nProvider built in %s/build/bin; no system configuration changed.\n' "$source_dir"
