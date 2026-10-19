use gost_sign_core::verification::{VerificationError, verify_certificate_signature_tc26_256_a};
const CERT: &[u8] =
    include_bytes!("../../gost-sign-experimental/tests/fixtures/rfc9215-tc26-256-a.der");

#[test]
fn verifies_the_published_rfc9215_certificate_without_csp() {
    assert_eq!(
        verify_certificate_signature_tc26_256_a(CERT, CERT),
        Ok(true)
    );
}
#[test]
fn changed_signed_content_and_signature_are_rejected() {
    let mut signature = CERT.to_vec();
    *signature.last_mut().expect("certificate is nonempty") ^= 1;
    assert_eq!(
        verify_certificate_signature_tc26_256_a(&signature, CERT),
        Ok(false)
    );
    let mut content = CERT.to_vec();
    let position = content
        .windows(b"Example".len())
        .position(|s| s == b"Example")
        .expect("RFC name");
    content[position] = b'e';
    assert_eq!(
        verify_certificate_signature_tc26_256_a(&content, CERT),
        Ok(false)
    );
}
#[test]
fn malformed_inputs_and_unsupported_parameters_are_errors() {
    for end in 0..CERT.len() {
        assert_eq!(
            verify_certificate_signature_tc26_256_a(&CERT[..end], CERT),
            Err(VerificationError::InvalidDer)
        );
        assert_eq!(
            verify_certificate_signature_tc26_256_a(CERT, &CERT[..end]),
            Err(VerificationError::InvalidDer)
        );
    }
    let mut wrong_curve = CERT.to_vec();
    let curve_oid = [
        0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01,
    ];
    let position = wrong_curve
        .windows(curve_oid.len())
        .position(|s| s == curve_oid)
        .expect("TC26A OID");
    wrong_curve[position + curve_oid.len() - 1] = 99;
    assert_eq!(
        verify_certificate_signature_tc26_256_a(CERT, &wrong_curve),
        Err(VerificationError::UnsupportedParameters)
    );
    let mut mismatch = CERT.to_vec();
    let algorithm_oid = [0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02];
    let pos = mismatch
        .windows(algorithm_oid.len())
        .rposition(|s| s == algorithm_oid)
        .expect("signature OID");
    mismatch[pos + algorithm_oid.len() - 1] = 3;
    assert_eq!(
        verify_certificate_signature_tc26_256_a(&mismatch, CERT),
        Err(VerificationError::AlgorithmMismatch)
    );
}
