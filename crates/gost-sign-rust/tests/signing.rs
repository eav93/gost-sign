use gost_sign_rust::SigningIdentity;
const CERT: &[u8] = include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
fn key() -> Vec<u8> {
    let mut der = vec![
        0x30, 0x3e, 0x02, 0x01, 0x00, 0x30, 0x17, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01,
        0x01, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01,
        0x04, 0x20, 0x01,
    ];
    der.extend_from_slice(&[0; 31]);
    der
}
#[test]
fn binding_randomized_signing_pfx_and_cms() {
    let identity = SigningIdentity::import_pkcs8(CERT, &key()).expect("public d=1");
    let a = identity.sign(b"document").expect("sign");
    let b = identity.sign(b"document").expect("sign");
    assert_ne!(a, b);
    assert_eq!(
        gost_sign_core::verification::verify_data_signature_gost2012_256(b"document", CERT, &a),
        Ok(true)
    );
    assert!(identity.export_pkcs12("").is_err());
    let pfx = identity.export_pkcs12("новый пароль").expect("export");
    assert!(SigningIdentity::import_pkcs12(&pfx, "incorrect").is_err());
    let restored = SigningIdentity::import_pkcs12(&pfx, "новый пароль").expect("import");
    let cms = restored.sign_cades(b"document").expect("CMS");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"document", &cms),
        Ok(true)
    );
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"modified", &cms),
        Ok(false)
    );
    for value in [0, 2, 255] {
        let mut wrong = key();
        wrong[32] = value;
        assert!(SigningIdentity::import_pkcs8(CERT, &wrong).is_err());
    }
    let mut trailing = key();
    trailing.push(0);
    assert!(SigningIdentity::import_pkcs8(CERT, &trailing).is_err());
}
#[test]
#[ignore = "requires GOST_CSP_FIXTURE_DIR: disposable test identity only"]
fn disposable_csp_container_to_rust_signature() {
    check_disposable_container("123456");
}
#[test]
#[ignore = "requires GOST_CSP_FIXTURE_DIR: disposable CSP identity created with --no-password"]
fn disposable_passwordless_csp_container_to_rust_signature() {
    check_disposable_container("");
}
fn check_disposable_container(password: &str) {
    let folder =
        std::path::PathBuf::from(std::env::var_os("GOST_CSP_FIXTURE_DIR").expect("test fixtures"));
    let raw = gost_sign_export::container::Container::from_directory(
        &folder.join("hdimage-test/gost-sig.000"),
    )
    .expect("raw");
    assert_eq!(
        raw.source_password_required().expect("password detection"),
        !password.is_empty()
    );
    assert!(raw.primary_pkcs8("wrong-test-password").is_err());
    let pkcs8 = raw.primary_pkcs8(password).expect("decode");
    let cert = std::fs::read(folder.join("test-csp.cer")).expect("cert");
    let identity = SigningIdentity::import_pkcs8(&cert, &pkcs8).expect("full key binding");
    let pfx = identity
        .export_pkcs12("new-portable-password")
        .expect("PFX");
    let restored = SigningIdentity::import_pkcs12(&pfx, "new-portable-password").expect("import");
    let content = b"Pure Rust GOST signing interoperability\0\xff\r\n";
    let cms = restored.sign_cades(content).expect("CMS");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(content, &cms),
        Ok(true)
    );
    std::fs::write(folder.join("rust-signed.p7s"), cms).expect("public output");
    std::fs::write(folder.join("rust-signed.bin"), content).expect("public content");
}
