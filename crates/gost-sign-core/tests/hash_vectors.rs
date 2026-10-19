use gost_sign_core::{hash256, hash512};
use hex_literal::hex;

// Official published vectors: https://www.rfc-editor.org/rfc/rfc6986#section-10
// The RFC prints mathematical vectors most-significant octet first; byte-stream
// APIs consume and return the reverse octet order. Reverse both sides explicitly
// so the source values remain directly auditable against the RFC.
fn check_rfc_vector<const N: usize>(mut message: [u8; N], mut h256: [u8; 32], mut h512: [u8; 64]) {
    message.reverse();
    h256.reverse();
    h512.reverse();
    assert_eq!(hash256(&message), h256);
    assert_eq!(hash512(&message), h512);
}

#[test]
fn rfc6986_example_one_short_message() {
    check_rfc_vector(
        hex!(
            "32313039383736353433323130393837
              36353433323130393837363534333231
              30393837363534333231303938373635
              343332313039383736353433323130"
        ),
        hex!("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d"),
        hex!(
            "486f64c1917879417fef082b3381a4e2
              11c324f074654c38823a7b76f830ad00
              fa1fbae42b1285c0352f227524bc9ab1
              6254288dd6863dccd5b9f54a1ad0541b"
        ),
    );
}

#[test]
fn rfc6986_example_two_multiblock_binary_message() {
    // 72 octets, containing non-UTF-8 bytes: no text transcoding is allowed.
    check_rfc_vector(
        hex!(
            "fbe2e5f0eee3c820fbeafaebef20fffb
              f0e1e0f0f520e0ed20e8ece0ebe5f0f2
              f120fff0eeec20f120faf2fee5e2202c
              e8f6f3ede220e8e6eee1e8f0f2d1202c
              e8f0f2e5e220e5d1"
        ),
        hex!("508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"),
        hex!(
            "28fbc9bada033b1460642bdcddb90c3f
              b3e56c497ccd0f62b8a2ad4935e85f03
              7613966de4ee00531ae60f3b5a47f8da
              e06915d5f2f194996fcabf2622e6881e"
        ),
    );
}

#[test]
fn rustcrypto_published_byte_order_vectors() {
    // https://docs.rs/streebog/0.11.0/streebog/
    assert_eq!(
        hash256(b"The quick brown fox jumps over the lazy dog"),
        hex!("3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4")
    );
    assert_eq!(
        hash512(b"The quick brown fox jumps over the lazy dog."),
        hex!(
            "fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be8
              2d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070"
        )
    );
}

#[test]
fn malformed_certificate_is_rejected() {
    assert!(gost_sign_core::parse_certificate_der(&[]).is_err());
    assert!(gost_sign_core::parse_certificate_der(b"not a certificate").is_err());
    assert!(gost_sign_core::parse_certificate_der(&[0x30, 0x00]).is_err());
}

#[test]
fn shared_php_fixture_matches_the_official_vectors() {
    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(pair, 16).expect("valid hexadecimal octet")
            })
            .collect()
    }
    let vectors: serde_json::Value = serde_json::from_str(include_str!("public-vectors.json"))
        .expect("valid shared fixture JSON");
    let vectors = vectors.as_array().expect("vector array");
    assert_eq!(vectors.len(), 2);
    for (vector, expected_length) in vectors.iter().zip([63, 72]) {
        let message = decode_hex(vector["input_hex"].as_str().expect("input hex"));
        let h256 = decode_hex(vector["hash256"].as_str().expect("256-bit digest hex"));
        let h512 = decode_hex(vector["hash512"].as_str().expect("512-bit digest hex"));
        assert_eq!(message.len(), expected_length);
        assert_eq!(h256.len(), 32);
        assert_eq!(h512.len(), 64);
        assert_eq!(hash256(&message).as_slice(), h256);
        assert_eq!(hash512(&message).as_slice(), h512);
    }
}
