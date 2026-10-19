# Сборка и GitHub Actions

Все команды ниже выполняются из корня исходного проекта.

## CLI локально

Версия toolchain закреплена в `rust-toolchain.toml` (1.98). Заявленный MSRV workspace 1.88 отдельно не проверен. На Linux перед сборкой установите `pkg-config` и `libpcsclite-dev` (Ubuntu/Debian). На Windows CLI использует стабильный Rust MSVC и инструменты сборки Visual Studio; nightly нужен только для PHP.

```sh
cargo build --locked --release -p gost-sign-rust --bin gost-sign --features pcsc
./target/release/gost-sign
```

Windows: `.\target\release\gost-sign.exe`. После копирования бинарника Cargo больше не нужен. Скрипт запуска не требуется. Для сборки без поддержки токена используйте `--features cli` вместо `--features pcsc`.

## Проверки

```sh
cargo fmt --all --check
cargo test --locked --release -p gost-sign-core -p gost-sign-experimental -p gost-sign-cms -p gost-sign-export -p gost-sign-pfx -p gost-sign-rust --features gost-sign-rust/pcsc
cargo clippy --locked --release -p gost-sign-core -p gost-sign-experimental -p gost-sign-cms -p gost-sign-export -p gost-sign-pfx -p gost-sign-rust --all-targets --features gost-sign-rust/pcsc -- -D warnings
```

Release-режим ускоряет тесты derivation пароля. Физическая карта и PC/SC-демон не нужны для unit/mock-тестов. Помеченные ignored тесты требуют явно предоставленных одноразовых фикстур, не запускаются в публичном CI.

## Матрица бинарников

Workflow `.github/workflows/binaries.yml`:

| ОС | Архитектура | Runner | Архив |
| --- | --- | --- | --- |
| Linux | x86_64 | ubuntu-24.04 | tar.gz |
| Linux | ARM64 | ubuntu-24.04-arm | tar.gz |
| macOS | Intel | macos-15-intel | tar.gz |
| macOS | Apple Silicon | macos-15 | tar.gz |
| Windows | x86_64 | windows-2025 | zip |
| Windows | ARM64 | windows-11-arm | zip |

Сборка нативная на соответствующем runner; workflow сверяет Rust host с ожидаемым target. Эти метки приведены в [GitHub hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Доступность/оплата runners зависит от репозитория и плана GitHub.

Запуск: ручной `workflow_dispatch` или вызов из release workflow. Проверки push/PR выполняет `ci.yml`, без дублирования архивных сборок. Workflow проверяет тесты, `--help`/`--version`, упаковывает бинарник с документацией, формирует SHA-256. Артефакты доступны в Actions → выбранный запуск → Artifacts, срок хранения 14 дней. Для установки скачайте artifact для своей платформы и распакуйте находящийся внутри архив.

Сам workflow бинарников только собирает артефакты с `contents: read`. Release workflow публикует их после успешной сборки всей матрицы; право `contents: write` выдано только задаче публикации. Версия архива берётся из собранного бинарника/Cargo.toml, не из имени тега. Перед версионным тегом обновите workspace version. BUILD-INFO содержит commit, target, Rust и признак незакоммиченных файлов.

Упаковка локально, например для текущего Mac:

```sh
bash scripts/package-cli.sh aarch64-apple-darwin
```

Windows PowerShell: `./scripts/package-cli.ps1 -Target x86_64-pc-windows-msvc`. Скрипты упаковки нужны разработчику, не конечному пользователю. Повторная упаковка с тем же именем не перезаписывает предыдущий архив.

В `dist/` попадают только явно перечисленные бинарник, README, docs, examples, licenses и BUILD-INFO. Ни `target/` целиком, ни PFX/контейнеры, ни локальные рабочие каталоги не архивируются. Unix tar сохраняет права исполняемого файла. Проверка хеша: `shasum -a 256 -c файл.tar.gz.sha256` на macOS, `sha256sum -c файл.tar.gz.sha256` на Linux; Windows — `Get-FileHash файл.zip -Algorithm SHA256` и сравнение с `.sha256`.

## Релизы

`release.yml` запускается при push тега `v<major>.<minor>.<patch>` или вручную с существующим тегом. Версия тега должна совпадать с workspace version в Cargo.toml. Workflow фиксирует commit тега, вызывает сборки CLI и PHP, затем публикует архивы и SHA-256 в [GitHub Releases](https://github.com/eav93/gost-sign/releases). Релиз не публикуется, пока хотя бы одна обязательная сборка не завершилась успешно.

```sh
git tag v0.1.0
git push origin v0.1.0
```

Имена CLI-архивов включают версию и Rust target. Имена PHP-архивов включают версию PHP, платформу и NTS/TS; версия проекта определяется релизом и commit в BUILD-INFO. Для загрузки PHP-модуля нужен тот же ABI PHP, режим потокобезопасности, архитектура и совместимая ОС. Linux-архивы не предназначены для Alpine/musl. Windows-модули требуют соответствующий Visual C++ runtime. На macOS файл модуля в архиве называется `.so`, но содержит Mach-O.

PHP-архив содержит `gost_sign_php.so` или `.dll`, `gost_sign.ini`, BUILD-INFO, документацию и пример. Скопируйте модуль в каталог `php-config --extension-dir` (на Unix) или `extension_dir` из `php -i`; добавьте `.ini` в конфигурацию именно нужного PHP. Для FPM конфигурация может отличаться от CLI; после подключения перезапустите FPM. Проверка загрузки:

```sh
php -r 'var_dump(function_exists("gost_sign_cades_sign_pfx"));'
```

## PHP


Workflow `ci.yml` проверяет Rust и PHP. Для быстрых PHP-проверок CI задана матрица 8.4/8.5. Отдельный `php-binaries.yml` собирает готовые расширения PHP 8.1–8.5: Linux/macOS x86_64/ARM64 NTS, Windows x64 NTS/ZTS. Каждый модуль загружается в PHP и проходит тест подписи из публичного PFX. Windows ARM64 PHP пока не включён. CLI-архивы не содержат PHP расширения, так как его ABI зависит от версии и сборки PHP.

```sh
cargo build --locked --release -p gost-sign-php
# macOS:
php -n -d extension=./target/release/libgost_sign_php.dylib crates/gost-sign-php/tests/smoke.php
# Linux: замените расширение файла на .so
```

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = 'rust-lld'
cargo +nightly build --locked --release -p gost-sign-php
php -n -d extension=./target/release/gost_sign_php.dll crates/gost-sign-php/tests/smoke.php
```

PHP SDK/режим NTS/ZTS должен совпадать с runtime; Windows ext-php-rs использует vectorcall и требует nightly. Основной CLI этого ограничения не имеет.

## Воспроизведение независимой проверки CSP

Необязательные скрипты `generate-csp-test-fixture.sh` и `verify-csp-test-signature.sh` требуют локальный лицензированный тестовый образ CSP. Они работают офлайн с одноразовыми ключами. Пример (имя образа замените своим):

```sh
bash scripts/generate-csp-test-fixture.sh local-csp-image target/csp-test
GOST_CSP_FIXTURE_DIR="$PWD/target/csp-test" cargo test --locked --release -p gost-sign-rust --test signing -- --ignored
bash scripts/verify-csp-test-signature.sh local-csp-image target/csp-test
```

Это не часть GitHub CI. Не подставляйте рабочие контейнеры вместо одноразовой тестовой фикстуры.
