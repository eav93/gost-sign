# Необязательный OpenSSL backend

Команды выполняются из корня исходного проекта. Этот backend не входит в готовый CLI.


Приоритет проекта — готовые криптобиблиотеки: RustCrypto для хеша/ASN.1/модульной арифметики, p12-keystore для PFX. Основной подписант — `gost-sign-rust`; OpenSSL backend ниже необязателен. Собственная variable-time арифметика остаётся экспериментальным независимым проверяющим модулем и не принимает закрытые ключи.

Backend использует OpenSSL >=3.4 и закреплённую ревизию `gost-engine` `509dcb467507149297673e68293be5b01d1aa4a8` (libprov `d5d381f71c90fe0c91f861784b715b189554f1f2`). Provider собирается внутри `tools/`, не меняя системные конфигурации; каталоги стороннего исходного кода и сборки не включаются в Git.

```sh
# macOS: берёт Homebrew openssl@3. Linux: предварительно задать OPENSSL_ROOT_DIR.
bash scripts/build-gost-provider.sh
export GOST_PROVIDER_MODULE="$PWD/tools/gost-engine/build/bin/gostprov.dylib"
# Linux обычно использует gostprov.so. Windows — scripts/build-gost-provider.ps1.
bash scripts/native-cargo.sh test --locked -p gost-sign-openssl --test provider -- --ignored
bash scripts/native-cargo.sh build --locked -p gost-sign-php --features native-openssl
php -n -d extension=./target/debug/libgost_sign_php.dylib crates/gost-sign-php/tests/native.php
```

```php
// Доступна только при сборке с native-openssl.
$cms = gost_sign_cades_sign_pkcs8($content, $certificateDer, $pkcs8Der, $providerModulePath);
$cms = gost_sign_cades_sign_encrypted_pkcs8(
    $content, $certificateDer, $encryptedPkcs8Der, $passwordBytes, $providerModulePath
);
$cms = gost_sign_cades_sign_pkcs12(
    $content, $pfxDer, $passwordUtf8, $providerModulePath, false // legacy algorithms opt-in
);
```

В Rust можно один раз загрузить ключ и повторно подписывать документы:

```rust,ignore
let provider = GostProvider::load(absolute_module_path)?;
let identity = provider.import_encrypted_pkcs8(certificate_der, encrypted_der, password_bytes)?;
// Либо: let identity = provider.import_pkcs12(pfx_der, password_utf8)?;
let cms = identity.sign_cades(content)?;
```

`SigningIdentity` удерживает ключ внутри OpenSSL, не имеет `Debug`, `Clone` и функции экспорта незашифрованного закрытого ключа. При импорте проверяется совпадение ключа с сертификатом; каждая подпись дополнительно проверяется Rust verifier. Исходные буферы и пароль принадлежат вызывающему коду, их очистка не гарантируется библиотекой. Зашифрованный ключ не записывается на диск в расшифрованном виде.

Пароль PKCS#8 передаётся как точные байты, включая NUL; слишком длинный пароль отклоняется без усечения. PFX API принимает UTF-8 без NUL. Проверяется отсутствие лишних байтов после DER. Дополнительные сертификаты цепочки из PFX не сохраняются и не означают доверия. Совместимость зависит от алгоритмов PFX и сборки OpenSSL; проверены PBES2/PBKDF2-SHA256/AES-256-CBC и стандартный PFX с MAC. Импорт CryptoPro PFX `.80` проверен через legacy-provider на одноразовом тестовом ключе CSP 5.0.13003. Стандартный PFX формируется и читается модулем gost-sign-pfx на Rust.

Provider загружается однократно с синхронизацией и сохраняется до завершения процесса. Попытка загрузить другую версию/путь после первой отклоняется. Это влияет на OpenSSL default context процесса, но не меняет системные файлы. Для старого PFX, требующего RC2, есть явный `provider.with_legacy()`; включение legacy также сохраняется до завершения процесса.

Тесты защищённого импорта и PHP (только публичный `d=1`, каталога назначения ещё не должно существовать):

```sh
bash scripts/native-cargo.sh run --locked -p gost-sign-openssl --example create_test_imports -- target/public-import-fixtures
export GOST_TEST_IMPORT_DIR="$PWD/target/public-import-fixtures"
php -n -d extension=./target/debug/libgost_sign_php.dylib crates/gost-sign-php/tests/imports.php
```

Тестовый PKCS#8 шифрует готовый RustCrypto `pkcs8`; тестовые salt/IV и параметры намеренно фиксированы и не подходят для рабочих ключей. На закреплённой версии provider удобный OpenSSL `private_key_to_pkcs8_passphrase` вернул обычный PKCS#8 вместо зашифрованного: эта функция не используется в рабочем API. Генератор тестовых файлов выводит только результат проверки формата, не ключевые байты.

На Mac собран provider с OpenSSL 3.6.3. Upstream выдаёт предупреждение об отсутствующем TLS-tree control в этой сборке OpenSSL; TLS не входит в проверенный сценарий. Подписание, native verification, Rust CMS verification и PHP binding прошли сквозной тест. Нативный backend на Linux/Windows пока не проверен, PowerShell-сборка подготовлена, но не запускалась. Основная матрица CI пока проверяет portable Rust и PHP без native backend.

Источники выбора: [gost-engine](https://github.com/gost-engine/engine), [Rust openssl](https://docs.rs/openssl/0.10.81/openssl/), [spodes GOST source](https://github.com/gvtret/spodes-rs/blob/main/src/security/gost3410.rs), [elliptic-curve-gost](https://docs.rs/elliptic-curve-gost/0.1.0/elliptic_curve_gost/).
