# Rust и PHP API

## Rust

Пакеты пока не публикуются в crates.io. Подключение из соседнего checkout:

```toml
[dependencies]
gost-sign-rust = { path = "../gost-sign/crates/gost-sign-rust" }
gost-sign-cms = { path = "../gost-sign/crates/gost-sign-cms" }
```

```rust,ignore
let identity = gost_sign_rust::SigningIdentity::import_pkcs12(&pfx_bytes, password)?;
// Объект можно использовать повторно; пароль нужен при открытии PFX.
let signature_der = identity.sign_cades(&document_bytes)?;
let valid = gost_sign_cms::verification::verify_detached(&document_bytes, &signature_der)?;
let pfx_with_new_password = identity.export_pkcs12(new_password)?;
```

`import_pkcs8(certificate_der, pkcs8_der)` принимает обычный PKCS#8 и сверяет полный открытый ключ. `certificate_der()` возвращает открытый сертификат. `sign(data)` возвращает 64 байта `s_BE || r_BE`, хешируя данные Streebog-256; это не prehash API. `sign_cades` возвращает DER CAdES-BES с сертификатом и подписанными атрибутами. `SigningIdentity` не реализует `Debug`/`Clone` и не предоставляет экспорт открытого закрытого ключа.

Для интеграции с внешним подписантом `PreparedDetachedSignature::new(content, certificate)` предоставляет точные `signed_attributes_der()` и `signing_digest()`. Внешний подписант подписывает атрибуты либо их хеш, без двойного хеширования; `finish(signature)` собирает CMS и сам по себе не проверяет подпись.

Низкоуровневый `gost-sign-pfx` только читает/пишет формат и не доказывает соответствие ключа сертификату. Для прикладной работы используйте `SigningIdentity`. `gost-sign-export` — библиотека чтения контейнера/PCSC, отдельного CLI больше нет.

## PHP

Скачайте расширение из Releases или соберите его под ту же версию PHP, архитектуру и режим ZTS/NTS, в котором будете его загружать. CLI-архив не содержит PHP-модуль. Подробности сборки — [build.md](build.md).

```php
$pfxBytes = file_get_contents('/private/identity.pfx');
$document = file_get_contents('/documents/invoice.pdf');
// $password предоставляет приложение, например из менеджера секретов.
$signature = gost_sign_cades_sign_pfx($document, $pfxBytes, $password);
file_put_contents('/documents/invoice.pdf.p7s', $signature);
$valid = gost_sign_cades_verify($document, $signature);
```

Все входные документы, PFX и CMS — бинарные строки. Хеш-функции `gost_sign_hash256`/`gost_sign_hash512` возвращают hex. Проверка неверной подписи возвращает `false`; повреждённый DER, неподдерживаемый профиль, неверный пароль и несовпадение ключа вызывают исключение.

Дополнительные функции: `gost_sign_cades_signed_attributes`, `gost_sign_cades_assemble`, `gost_sign_verify_certificate_tc26_256_a`. Последняя проверяет математическую подпись сертификата заданным ключом издателя без доверия цепочке.

Функции старого OpenSSL backend включаются только feature `native-openssl`; [отдельная инструкция](legacy-openssl.md). Основной `gost_sign_cades_sign_pfx` не загружает провайдеров и не требует `GOST_PROVIDER_MODULE`.

## Запускаемые примеры

- `crates/gost-sign-rust/examples/export_container.rs` — контейнер → PFX.
- `crates/gost-sign-rust/examples/sign_pfx.rs` — PFX → CAdES.
- `examples/php/sign.php` — подпись и проверка в PHP.

[Команды запуска и экспорт с Рутокен](export.md).

## Владение секретами

Ключ и PKCS#8 в Rust-объекте используют `Zeroizing`. Буферы пароля/PFX, переданные приложением, принадлежат вызывающему коду; их срок жизни определяет приложение. PHP-строки и внутренние копии зависимостей не гарантированно очищаются. Не выводите содержимое контейнеров и пароли в логи. См. [ограничения](architecture.md).
