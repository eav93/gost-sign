//! Uses ONLY newly generated disposable CSP test fixtures, never a production identity.
use gost_sign_openssl::GostProvider;
#[test]
#[ignore = "requires GOST_PROVIDER_MODULE and GOST_CSP_FIXTURE_DIR (disposable test identity)"]
fn imports_csp_export_and_signs_without_csp() {
    let module = std::env::var_os("GOST_PROVIDER_MODULE").expect("module");
    let folder = std::path::PathBuf::from(
        std::env::var_os("GOST_CSP_FIXTURE_DIR").expect("test fixture dir"),
    );
    let provider = GostProvider::load(std::path::Path::new(&module))
        .expect("load")
        .with_legacy()
        .expect("legacy PFX encryption");
    let pfx = std::fs::read(folder.join("test-csp.pfx")).expect("test PFX");
    // Confirm that this fixture exercises the proprietary CryptoPro PBE OID .80.
    assert!(pfx.windows(12).any(|w| w
        == [
            0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x50
        ]));
    let cert = std::fs::read(folder.join("test-csp.cer")).expect("test cert");
    let raw = gost_sign_export::container::Container::from_directory(
        &folder.join("hdimage-test/gost-sig.000"),
    )
    .expect("raw source");
    assert!(raw.primary_pkcs8("incorrect").is_err());
    let pkcs8 = raw
        .primary_pkcs8("123456")
        .expect("native Rust source decryption");
    let raw_identity = provider
        .import_pkcs8(&cert, &pkcs8)
        .expect("full public-key binding");
    let portable = raw_identity
        .export_pkcs12("new-portable-password")
        .expect("standard Rust PFX export");
    let portable_identity = provider
        .import_standard_pkcs12(&portable, "new-portable-password")
        .expect("standard Rust PFX import");
    assert!(
        provider
            .import_standard_pkcs12(&portable, "123456")
            .is_err()
    );
    assert!(
        portable_identity
            .sign_cades(b"raw-container portable PFX")
            .is_ok()
    );
    let identity = provider
        .import_pkcs12(&pfx, "123456")
        .expect("CSP PFX import");
    assert_eq!(identity.certificate_der(), cert);
    let content = b"CSP export / independent signing interop\0\xff\r\n";
    let cms = portable_identity
        .sign_cades(content)
        .expect("sign migrated container without CSP");
    assert_eq!(
        gost_sign_cms::verification::verify_detached(content, &cms),
        Ok(true)
    );
    assert_eq!(
        gost_sign_cms::verification::verify_detached(b"changed", &cms),
        Ok(false)
    );
    assert!(
        provider
            .import_pkcs12(&pfx, "incorrect-test-password")
            .is_err()
    );
    // Only the public CMS/content are written back for an optional CSP-side verifier.
    std::fs::write(folder.join("rust-signed.p7s"), cms).expect("write public CMS");
    std::fs::write(folder.join("rust-signed.bin"), content).expect("write public content");
}
