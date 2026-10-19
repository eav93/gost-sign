pub const CERT: &[u8] =
    include_bytes!("../../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
// Deliberately public test scalar d=1, never a user's key.
pub fn public_test_key() -> Vec<u8> {
    let mut der = vec![
        0x30, 0x3e, 0x02, 0x01, 0x00, 0x30, 0x17, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01,
        0x01, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01,
        0x04, 0x20, 0x01,
    ];
    der.extend_from_slice(&[0; 31]);
    der
}

// Independent ready-made RustCrypto PBES2 encoder. Fixed salt/IV and low work
// factor are deliberately TEST ONLY: the scalar is public d=1 (or d=2).
pub fn encrypted_test_key(key: &[u8], password: &[u8]) -> Vec<u8> {
    use pkcs8::der::Decode;
    let params = pkcs8::pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(
        2048,
        b"public-test-salt!",
        [42; 16],
    )
    .expect("test PBES2 parameters");
    pkcs8::PrivateKeyInfoRef::from_der(key)
        .expect("test PKCS8")
        .encrypt_with_params(params, password)
        .expect("encrypt public fixture")
        .as_bytes()
        .to_vec()
}
