//! Run in an isolated process deliberately linked against a different libcrypto.
#[test]
#[ignore = "requires deliberately mismatched OpenSSL and GOST_PROVIDER_MODULE"]
fn rejects_missing_global_provider_registration() {
    let path = std::env::var_os("GOST_PROVIDER_MODULE").expect("module path");
    assert!(matches!(
        gost_sign_openssl::GostProvider::load(std::path::Path::new(&path)),
        Err(gost_sign_openssl::Error::IncompatibleProvider)
    ));
}
