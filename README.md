# gost-sign

Библиотека ГОСТ 2012-256 на Rust, консольная утилита и PHP-расширение.

## Возможности

- Создание и проверка отсоединённых подписей CAdES-BES.
- Импорт и экспорт PKCS#12/PFX с обязательным паролем.
- Перенос ключа и сертификата из локального контейнера КриптоПро или Рутокен Lite 1010.
- Экспорт сертификата X.509 DER.
- Поиск контейнеров КриптоПро и Рутокен с выбором по владельцу, организации/ИП и сроку сертификата.
- Streebog-256 и Streebog-512.

Основной модуль не зависит от КриптоПро и OpenSSL. Поддерживаемые кривые: TC26-256-A, CryptoPro-A, CryptoPro-XchA и TC26-256-B. Подпись ГОСТ-512 не поддерживается.

## Установка

Скачайте архив для своей платформы из [Releases](https://github.com/eav93/gost-sign/releases). Контрольные суммы доступны в файлах `.sha256`.

| Компонент | Платформы |
| --- | --- |
| CLI | Linux, macOS, Windows — x86_64 и ARM64 |
| PHP 8.1–8.5 | Linux/macOS x86_64 и ARM64 — NTS; Windows x64 — NTS/ZTS |

Архив CLI содержит один исполняемый файл. Установка Rust не требуется. Linux-сборка требует glibc и `libpcsclite1`; для работы с токеном нужны служба PC/SC и драйвер устройства. [Системные требования](docs/usage.md#установка).

Зависимости для Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends libc6 libpcsclite1
```

glibc входит в пакет `libc6` и обычно уже установлена. Для подключения токена см. [установку PC/SC и проверку считывателя](docs/usage.md#зависимости-linux).

## CLI

Linux/macOS:

```sh
./gost-sign
```

Windows PowerShell:

```powershell
.\gost-sign.exe
```

Интерактивное меню: выбор и смена контейнера, подпись документа, проверка подписи, перенос ключа в PFX, экспорт сертификата. Пароли вводятся скрыто. Существующие файлы не перезаписываются.

```sh
gost-sign --help
gost-sign --version
gost-sign --list-containers
```

## PHP

Выберите расширение для своей версии PHP, архитектуры и режима NTS/ZTS. Скопируйте модуль в `extension_dir` и подключите прилагаемый `gost_sign.ini`.

```php
$pfx = file_get_contents('/keys/identity.pfx');
$document = file_get_contents('/documents/invoice.pdf');
$signature = gost_sign_cades_sign_pfx($document, $pfx, $password);
file_put_contents('/documents/invoice.pdf.p7s', $signature);
$valid = gost_sign_cades_verify($document, $signature);
```

## Rust

```rust,ignore
use gost_sign_rust::SigningIdentity;

let identity = SigningIdentity::import_pkcs12(&pfx, password)?;
let signature = identity.sign_cades(&document)?;
let valid = gost_sign_cms::verification::verify_detached(&document, &signature)?;
```

Пакеты подключаются из исходного репозитория; публикации в crates.io нет.

## Сборка

```sh
cargo build --locked --release -p gost-sign-rust --bin gost-sign --features pcsc
cargo build --locked --release -p gost-sign-php
```

Версия Rust задана в `rust-toolchain.toml`. PHP-расширение требует совместимый PHP SDK; на Windows — Rust nightly. [Сборка и CI](docs/build.md).

## Ограничения

Проверка подписи не включает доверие цепочке, срок действия и отзыв сертификата. Поддерживается ограниченный профиль CAdES-BES и шестифайлового контейнера КриптоПро. Работа PC/SC проверена на имитации карты; проверка на физическом Рутокен Lite не завершена. Независимый криптографический аудит и сертификация не проводились.

## Документация

- [Руководство пользователя](docs/usage.md)
- [Экспорт из контейнера и Рутокен, примеры кода](docs/export.md)
- [Rust и PHP API](docs/api.md)
- [Сборка, CI и релизы](docs/build.md)
- [Архитектура и форматы](docs/architecture.md)
- [Совместимость со старым PFX КриптоПро](docs/legacy-openssl.md)
- [Артефакты и очистка](docs/artifacts.md)
