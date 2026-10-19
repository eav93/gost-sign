use gost_sign_experimental::verify_tc26_256_a;
use streebog::{Digest, Streebog256};
use x509_cert::{
    Certificate,
    der::{Decode, Encode, asn1::OctetString},
};

// Public official certificate from RFC 9215 Appendix D.2.2, verbatim DER.
const CERT: &[u8] = include_bytes!("fixtures/rfc9215-tc26-256-a.der");
fn vector() -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let certificate = Certificate::from_der(CERT).expect("official RFC certificate");
    let tbs = certificate.tbs_certificate().to_der().expect("TBS DER");
    let spki = certificate.tbs_certificate().subject_public_key_info();
    let wrapped_key = spki
        .subject_public_key
        .as_bytes()
        .expect("byte aligned key");
    let key = OctetString::from_der(wrapped_key).expect("public key OCTET STRING");
    (
        Streebog256::digest(&tbs).into(),
        key.as_bytes().to_vec(),
        certificate
            .signature()
            .as_bytes()
            .expect("byte aligned signature")
            .to_vec(),
    )
}
#[test]
fn verifies_official_rfc9215_certificate_signature() {
    let (digest, key, signature) = vector();
    assert!(verify_tc26_256_a(&digest, &key, &signature));
}
#[test]
fn rejects_corrupted_or_wrongly_encoded_values() {
    let (digest, key, signature) = vector();
    let mut changed = digest;
    changed[0] ^= 1;
    assert!(!verify_tc26_256_a(&changed, &key, &signature));
    for index in [0, 31, 32, 63] {
        let mut bad = signature.clone();
        bad[index] ^= 1;
        assert!(!verify_tc26_256_a(&digest, &key, &bad));
    }
    let mut reversed = signature.clone();
    reversed.reverse();
    assert!(!verify_tc26_256_a(&digest, &key, &reversed));
    let mut reversed_key = key.clone();
    reversed_key[..32].reverse();
    reversed_key[32..].reverse();
    assert!(!verify_tc26_256_a(&digest, &reversed_key, &signature));
    for length in [0, 31, 32, 63] {
        assert!(!verify_tc26_256_a(&digest, &key[..length], &signature));
        assert!(!verify_tc26_256_a(&digest, &key, &signature[..length]));
    }
    assert!(!verify_tc26_256_a(&digest, &[0; 64], &signature));
    assert!(!verify_tc26_256_a(&digest, &[255; 64], &signature));
    assert!(!verify_tc26_256_a(&digest, &key, &[0; 64]));
    assert!(!verify_tc26_256_a(&digest, &key, &[255; 64]));
}
