use gost_sign_core::parse_certificate_der;
use hex_literal::hex;

// Deliberately unsigned synthetic DER: no real identity or private-key material.
// A successful parse does not imply a valid signature or trusted certificate.
const SYNTHETIC_CERTIFICATE: &[u8] = &hex!(
    "3081e5308193020101300a06082a850307010103023000301e170d3236303130313030303030305a170d3237303130313030303030305a3000305e301706082a85030701010101300b06092a8503070102010101034300044000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300a06082a8503070101030203410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
);

#[test]
fn reads_public_algorithm_and_parameters_without_csp() {
    let certificate = parse_certificate_der(SYNTHETIC_CERTIFICATE).expect("synthetic DER");
    assert_eq!(
        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
            .to_string(),
        "1.2.643.7.1.1.1.1"
    );
    assert!(
        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .parameters
            .is_some()
    );
    assert_eq!(
        certificate.signature_algorithm().oid.to_string(),
        "1.2.643.7.1.1.3.2"
    );
}

#[test]
fn rejects_truncated_certificates_and_trailing_data() {
    for end in 0..SYNTHETIC_CERTIFICATE.len() {
        assert!(parse_certificate_der(&SYNTHETIC_CERTIFICATE[..end]).is_err());
    }
    let mut extra = SYNTHETIC_CERTIFICATE.to_vec();
    extra.push(0);
    assert!(parse_certificate_der(&extra).is_err());
}
