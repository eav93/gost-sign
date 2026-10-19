#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PACKAGE_PLATFORM:?Укажите платформу}"
: "${PHP_VERSION:?Укажите версию PHP}"
case "$PACKAGE_PLATFORM" in
  macos-aarch64|macos-x86_64) extension=target/release/libgost_sign_php.dylib ;;
  linux-aarch64|linux-x86_64) extension=target/release/libgost_sign_php.so ;;
  *) echo 'Неподдерживаемая платформа' >&2; exit 1 ;;
esac
php -n -r 'exit(PHP_ZTS ? 1 : 0);'
actual_php=$(php -n -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')
[[ "$PHP_VERSION" = "$actual_php" ]] || { echo 'Версия PHP не совпадает' >&2; exit 1; }
php -n -d "extension=$PWD/$extension" crates/gost-sign-php/tests/smoke.php
php -n -d "extension=$PWD/$extension" crates/gost-sign-php/tests/portable.php target/php-public-test.pfx
package="gost-sign-php$PHP_VERSION-$PACKAGE_PLATFORM-nts"
mkdir -p dist
[[ ! -e "dist/$package" && ! -e "dist/$package.tar.gz" ]] || { echo 'Архив уже существует' >&2; exit 1; }
mkdir "dist/$package"
# PHP загружает Mach-O и ELF под общим именем расширения .so.
cp "$extension" "dist/$package/gost_sign_php.so"
printf '; Скопируйте модуль в extension_dir или укажите абсолютный путь.\nextension=gost_sign_php.so\n' > "dist/$package/gost_sign.ini"
cp README.md "dist/$package/"
cp -R docs licenses examples "dist/$package/"
{ git rev-parse HEAD; rustc --version; php -n -i | sed -n '/^PHP API /p;/^PHP Extension /p;/^Zend Extension /p;/^Thread Safety /p;/^Debug Build /p'; } > "dist/$package/BUILD-INFO.txt"
tar -czf "dist/$package.tar.gz" -C dist "$package"
(cd dist; if command -v sha256sum >/dev/null 2>&1; then sha256sum "$package.tar.gz"; else shasum -a 256 "$package.tar.gz"; fi) > "dist/$package.tar.gz.sha256"
printf 'Готово: dist/%s.tar.gz\n' "$package"
