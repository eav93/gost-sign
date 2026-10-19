use gost_sign_openssl::GostProvider;
mod common;
use common::{CERT, encrypted_test_key, public_test_key};
#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn ready_provider_signs_and_rust_verifies_cades() {
    let module = std::env::var_os("GOST_PROVIDER_MODULE").expect("provider module path");
    let provider = GostProvider::load(std::path::Path::new(&module)).expect("load provider");
    let data = b"Test-only native provider signing\0\xff\r\n";
    let prepared = gost_sign_cms::PreparedDetachedSignature::new(data, CERT).expect("prepare");
    let signature = provider
        .sign(prepared.signed_attributes_der(), CERT, &public_test_key())
        .expect("native sign");
    assert_eq!(signature.len(), 64);
    assert!(
        provider
            .verify(prepared.signed_attributes_der(), CERT, &signature)
            .expect("native verify")
    );
    let cms = prepared.finish(&signature).expect("assemble");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(data, &cms),
        Ok(true)
    );
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"changed", &cms),
        Ok(false)
    );
    let mut wrong_key = public_test_key();
    wrong_key[32] = 2; // scalar d=2 (little endian), different public key
    assert!(matches!(
        provider.sign(data, CERT, &wrong_key),
        Err(gost_sign_openssl::Error::KeyMismatch)
    ));
    assert!(provider.sign(data, CERT, b"not PKCS8").is_err());
}

fn provider() -> GostProvider {
    let path = std::env::var_os("GOST_PROVIDER_MODULE").expect("provider module path");
    GostProvider::load(std::path::Path::new(&path)).expect("load provider")
}

#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn encrypted_pkcs8_import_checks_password_key_binding_and_exact_der() {
    let provider = provider();
    let password = b"public-test-password\0binary";
    let encrypted = encrypted_test_key(&public_test_key(), password);
    let identity = provider
        .import_encrypted_pkcs8(CERT, &encrypted, password)
        .expect("import encrypted key");
    assert_eq!(identity.certificate_der(), CERT);
    for data in [
        b"first\0message".as_slice(),
        b"second\xffmessage".as_slice(),
    ] {
        let cms = identity.sign_cades(data).expect("reusable identity signs");
        assert_eq!(
            gost_sign_cms::verification::verify_detached(data, &cms),
            Ok(true)
        );
    }
    assert!(
        provider
            .import_encrypted_pkcs8(CERT, &encrypted, b"wrong")
            .is_err()
    );
    assert!(
        provider
            .import_encrypted_pkcs8(CERT, &encrypted, b"public-test-password")
            .is_err()
    );
    assert!(matches!(
        provider.import_encrypted_pkcs8(CERT, &encrypted, &[42; 4096]),
        Err(gost_sign_openssl::Error::PasswordTooLong)
    ));
    assert!(
        provider
            .import_encrypted_pkcs8(CERT, &public_test_key(), password)
            .is_err()
    );
    let mut trailing = encrypted.clone();
    trailing.push(0);
    assert!(matches!(
        provider.import_encrypted_pkcs8(CERT, &trailing, password),
        Err(gost_sign_openssl::Error::InvalidDer)
    ));
    let mut wrong = public_test_key();
    wrong[32] = 2;
    let wrong = encrypted_test_key(&wrong, password);
    assert!(matches!(
        provider.import_encrypted_pkcs8(CERT, &wrong, password),
        Err(gost_sign_openssl::Error::KeyMismatch)
    ));
    assert!(
        provider
            .import_encrypted_pkcs8(CERT, &encrypted[..encrypted.len() - 1], password)
            .is_err()
    );
}

#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn portable_pfx_export_requires_only_new_password() {
    let provider = provider();
    let encrypted = common::encrypted_test_key(&public_test_key(), b"old source PIN");
    let identity = provider
        .import_encrypted_pkcs8(CERT, &encrypted, b"old source PIN")
        .expect("source import");
    assert!(identity.export_pkcs12("").is_err());
    assert!(identity.export_pkcs12("bad\0password").is_err());
    let exported = identity
        .export_pkcs12("new portable password")
        .expect("export");
    assert!(provider.import_pkcs12(&exported, "old source PIN").is_err());
    assert!(provider.import_pkcs12(&exported, "").is_err());
    let restored = provider
        .import_pkcs12(&exported, "new portable password")
        .expect("portable import");
    let rust_import = provider
        .import_standard_pkcs12(&exported, "new portable password")
        .expect("Rust PFX import");
    assert_eq!(rust_import.certificate_der(), restored.certificate_der());
    assert!(rust_import.sign_cades(b"Rust PFX parser").is_ok());
    let signature = restored.sign_cades(b"portable PFX test").expect("sign");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"portable PFX test", &signature),
        Ok(true)
    );
    // PKCS#12 shroudedKeyBag OID, not the proprietary CryptoPro PBE .80.
    assert!(
        exported
            .windows(13)
            .any(|w| w == [6, 11, 42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 2])
    );
    assert!(
        !exported
            .windows(public_test_key().len())
            .any(|w| w == public_test_key())
    );
}

#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn pfx_import_checks_password_integrity_and_identity() {
    use openssl::{hash::MessageDigest, nid::Nid, pkcs12::Pkcs12, pkey::PKey, x509::X509};
    let provider = provider();
    let key = PKey::private_key_from_pkcs8(&public_test_key()).expect("test key");
    let cert = X509::from_der(CERT).expect("public test cert");
    let password = "тестовый password";
    let pfx = Pkcs12::builder()
        .pkey(&key)
        .cert(&cert)
        .key_algorithm(Nid::AES_256_CBC)
        .cert_algorithm(Nid::AES_256_CBC)
        .mac_md(MessageDigest::sha256())
        .build2(password)
        .expect("test PFX")
        .to_der()
        .expect("PFX DER");
    let identity = provider.import_pkcs12(&pfx, password).expect("PFX import");
    let cms = identity.sign_cades(b"PFX\0content").expect("sign");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"PFX\0content", &cms),
        Ok(true)
    );
    assert!(provider.import_pkcs12(&pfx, "wrong").is_err());
    assert!(matches!(
        provider.import_pkcs12(&pfx, "test\0suffix"),
        Err(gost_sign_openssl::Error::InvalidPassword)
    ));
    let mut changed = pfx.clone();
    let n = changed.len();
    changed[n - 8] ^= 1;
    assert!(provider.import_pkcs12(&changed, password).is_err());
    let mut trailing = pfx;
    trailing.push(0);
    assert!(matches!(
        provider.import_pkcs12(&trailing, password),
        Err(gost_sign_openssl::Error::InvalidDer)
    ));
    let cert_only = Pkcs12::builder()
        .cert(&cert)
        .build2(password)
        .expect("certificate-only PFX")
        .to_der()
        .expect("DER");
    assert!(matches!(
        provider.import_pkcs12(&cert_only, password),
        Err(gost_sign_openssl::Error::MissingIdentity)
    ));
}

#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn concurrent_provider_handles_and_identities() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let provider = provider();
                let identity = provider
                    .import_pkcs8(CERT, &public_test_key())
                    .expect("import");
                let cms = identity.sign_cades(b"parallel imports").expect("sign");
                assert_eq!(
                    gost_sign_cms::verification::verify_detached(b"parallel imports", &cms),
                    Ok(true)
                );
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("worker did not panic");
    }
}

#[test]
#[ignore = "requires a locally built GOST_PROVIDER_MODULE"]
fn pure_rust_signatures_verify_in_independent_provider() {
    let provider = provider();
    let identity = gost_sign_rust::SigningIdentity::import_pkcs8(CERT, &public_test_key())
        .expect("Rust binding");
    for data in [
        b"".as_slice(),
        b"binary\0\xff\r\n",
        b"TC26-A portable signing",
    ] {
        let signature = identity.sign(data).expect("Rust signing");
        assert!(
            provider
                .verify(data, CERT, &signature)
                .expect("OpenSSL verification")
        );
    }
}
