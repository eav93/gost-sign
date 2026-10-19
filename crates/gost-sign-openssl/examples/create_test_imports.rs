//! Generate only PUBLIC d=1 test key containers for PHP interop tests.
#[path = "../tests/common/mod.rs"]
mod common;
use openssl::{hash::MessageDigest, nid::Nid, pkcs12::Pkcs12, pkey::PKey, x509::X509};
use std::{fs::OpenOptions, io::Write, path::Path};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("usage: create_test_imports <new-directory>")?;
    let output = Path::new(&output);
    std::fs::create_dir(output)?;
    let module = std::env::var_os("GOST_PROVIDER_MODULE").ok_or("set GOST_PROVIDER_MODULE")?;
    let _provider = gost_sign_openssl::GostProvider::load(Path::new(&module))?;
    let key = PKey::private_key_from_pkcs8(&common::public_test_key())?;
    // Diagnose the provider encoder using public data only; never persist this output.
    use pkcs8::der::Decode;
    let encoded =
        key.private_key_to_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"public-probe")?;
    println!(
        "Native encoder metadata: encrypted={}, plain={}",
        pkcs8::EncryptedPrivateKeyInfoRef::from_der(&encoded).is_ok(),
        pkcs8::PrivateKeyInfoRef::from_der(&encoded).is_ok()
    );
    let cert = X509::from_der(common::CERT)?;
    let pfx = Pkcs12::builder()
        .pkey(&key)
        .cert(&cert)
        .key_algorithm(Nid::AES_256_CBC)
        .cert_algorithm(Nid::AES_256_CBC)
        .mac_md(MessageDigest::sha256())
        .build2("public-test-pfx")?
        .to_der()?;
    let encrypted =
        common::encrypted_test_key(&common::public_test_key(), b"public-test-password\0binary");
    for (name, data) in [
        ("encrypted-pkcs8.der", encrypted),
        ("test-identity.pfx", pfx),
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))?
            .write_all(&data)?;
    }
    println!("Created PUBLIC d=1 test containers; never use this key for real signing.");
    Ok(())
}
