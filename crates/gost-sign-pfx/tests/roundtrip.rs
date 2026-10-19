#[allow(dead_code)]
#[path = "../../gost-sign-openssl/tests/common/mod.rs"]
mod common;
use gost_sign_pfx::{export, import};

#[test]
fn standard_gost_pfx_roundtrip_and_rejections() {
    let key = common::public_test_key();
    let password = "Новый пароль PFX";
    let encoded = export(&key, common::CERT, password).expect("export");
    let decoded = import(&encoded, password).expect("import");
    assert_eq!(decoded.pkcs8_der(), key);
    assert_eq!(decoded.certificate_der(), common::CERT);
    assert!(import(&encoded, "wrong").is_err());
    assert!(export(&key, common::CERT, "").is_err());
    assert!(export(&key, common::CERT, "bad\0pass").is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(import(&trailing, password).is_err());
    let mut tampered = encoded.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(import(&tampered, password).is_err());
    assert!(import(&encoded[..encoded.len() - 1], password).is_err());
    assert_ne!(
        export(&key, common::CERT, password).expect("random salts"),
        encoded
    );
    use der::{Decode, Encode};
    let mut no_mac = pkcs12::pfx::Pfx::from_der(&encoded).expect("PFX");
    no_mac.mac_data = None;
    assert!(import(&no_mac.to_der().expect("DER"), password).is_err());
}
