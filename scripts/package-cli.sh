#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
package_target="${1:?Укажите Rust target, например aarch64-apple-darwin}"
case "$package_target" in
  aarch64-apple-darwin|x86_64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-unknown-linux-gnu) ;;
  *) echo 'Неподдерживаемая платформа Unix' >&2; exit 1 ;;
esac
binary=target/release/gost-sign
version="$($binary --version)"
version="${version#gost-sign }"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Неверная версия бинарника' >&2; exit 1; }
package="gost-sign-$version-$package_target"
mkdir -p dist
[[ ! -e "dist/$package" && ! -e "dist/$package.tar.gz" ]] || { echo 'Архив уже существует; выберите пустую папку dist' >&2; exit 1; }
mkdir "dist/$package"
cp "$binary" "dist/$package/"
chmod 755 "dist/$package/gost-sign"
cp README.md "dist/$package/"
cp -R docs licenses examples "dist/$package/"
revision="${BUILD_REVISION:-$(git rev-parse HEAD)}"
{
  printf 'version=%s\ntarget=%s\nrevision=%s\n' "$version" "$package_target" "$revision"
  printf 'source_dirty=%s\n' "$(test -z "$(git status --porcelain)" && echo false || echo true)"
  rustc --version
} > "dist/$package/BUILD-INFO.txt"
tar -czf "dist/$package.tar.gz" -C dist "$package"
(
  cd dist
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$package.tar.gz" > "$package.tar.gz.sha256"
  else
    shasum -a 256 "$package.tar.gz" > "$package.tar.gz.sha256"
  fi
)
printf 'Готово: dist/%s.tar.gz\n' "$package"
