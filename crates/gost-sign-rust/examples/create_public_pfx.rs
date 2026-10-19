//! Только публичная фикстура d=1 для smoke-тестов PHP, не генератор рабочих ключей.
use std::io::Write;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("Укажите новый путь тестового PFX")?;
    let mut key = vec![
        0x30, 0x3e, 0x02, 0x01, 0x00, 0x30, 0x17, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01,
        0x01, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01,
        0x04, 0x20, 0x01,
    ];
    key.extend_from_slice(&[0; 31]);
    let cert = include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
    let identity = gost_sign_rust::SigningIdentity::import_pkcs8(cert, &key)?;
    let pfx = identity.export_pkcs12("test-new-password")?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?
        .write_all(&pfx)?;
    println!("Создана публичная тестовая фикстура. Не используйте её для рабочих документов.");
    Ok(())
}
