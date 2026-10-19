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

`gost_sign_rust::generate_pfx_password()?` возвращает `Zeroizing<String>`: случайный пароль из 32 ASCII-символов (192 бита случайности ОС). Библиотека не выводит и не сохраняет его. Передайте пароль в `export_pkcs12(&password)` и обеспечьте его сохранение в приложении. Сам `export_pkcs12` продолжает отклонять пустой пароль; автоматическая генерация по Enter относится к интерактивному CLI и примеру `export_container`.

`import_pkcs8(certificate_der, pkcs8_der)` принимает обычный PKCS#8 и сверяет полный открытый ключ. `certificate_der()` возвращает открытый сертификат. `sign(data)` возвращает 64 байта `s_BE || r_BE`, хешируя данные Streebog-256; это не prehash API. `sign_cades` возвращает DER CAdES-BES с сертификатом и подписанными атрибутами. `SigningIdentity` не реализует `Debug`/`Clone` и не предоставляет экспорт открытого закрытого ключа.

Для интеграции с внешним подписантом `PreparedDetachedSignature::new(content, certificate)` предоставляет точные `signed_attributes_der()` и `signing_digest()`. Внешний подписант подписывает атрибуты либо их хеш, без двойного хеширования; `finish(signature)` собирает CMS и сам по себе не проверяет подпись.

Низкоуровневый `gost-sign-pfx` только читает/пишет формат и не доказывает соответствие ключа сертификату. Для прикладной работы используйте `SigningIdentity`. `gost-sign-export` — библиотека чтения контейнера/PCSC, отдельного CLI больше нет.

### Поиск контейнеров

`gost_sign_export::discovery::system()` проверяет стандартные хранилища КриптоПро. Для заданных папок используйте `discovery::directories(&roots)`. Поиск читает открытые заголовки без пароля и возвращает источники, сертификаты DER и сообщения об ошибках доступа:

```rust,ignore
let report = gost_sign_export::discovery::system();
for entry in &report.entries {
    println!("{}: сертификатов — {}", entry.source.label(), entry.certificates.len());
}
// После выбора пользователем: entry.source.load()? читает полный контейнер.
```

Для Рутокен при включённой feature `pcsc` доступны `token::readers()` и `token::discover(reader, progress)`. Поиск возвращает каталоги карты и открытые сертификаты, не отправляя PIN. Полное чтение выполняется отдельно через `token::container_with_pin`; callback запроса PIN вызывается только при отказе чтения из-за отсутствия авторизации. Обнаружение контейнера не гарантирует доступность его закрытого ключа для экспорта.

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

`gost_sign_pfx_certificate($pfxBytes, $password)` возвращает сертификат X.509 DER после проверки пароля и соответствия ключу. Его SHA-1 отпечаток для API ЭДО: `strtoupper(sha1($certificateDer))`.

Дополнительные функции: `gost_sign_cades_signed_attributes`, `gost_sign_cades_assemble`, `gost_sign_verify_certificate_tc26_256_a`. Последняя проверяет математическую подпись сертификата заданным ключом издателя без доверия цепочке.

Функции старого OpenSSL backend включаются только feature `native-openssl`; [отдельная инструкция](legacy-openssl.md). Основной `gost_sign_cades_sign_pfx` не загружает провайдеров и не требует `GOST_PROVIDER_MODULE`.

## Запускаемые примеры

- `crates/gost-sign-rust/examples/export_container.rs` — контейнер → PFX.
- `crates/gost-sign-rust/examples/sign_pfx.rs` — PFX → CAdES.
- `examples/php/sign.php` — подпись и проверка в PHP.

[Команды запуска и экспорт с Рутокен](export.md).

## Владение секретами

Ключ и PKCS#8 в Rust-объекте используют `Zeroizing`. Буферы пароля/PFX, переданные приложением, принадлежат вызывающему коду; их срок жизни определяет приложение. PHP-строки и внутренние копии зависимостей не гарантированно очищаются. Не выводите содержимое контейнеров и пароли в логи. См. [ограничения](architecture.md).
