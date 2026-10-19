//! Experimental CryptoPro 256-bit software-container decoding.
//! Reference: li0ard/cpfx_ts and li0ard/gost (MIT), RFC 5830/8891.
//! A signer MUST verify the full derived public key against the certificate.
use crate::container::{Container, Result};
use crypto_bigint::{U256, const_monty_form, const_monty_params, modular::ConstMontyParams};
use der::{
    Decode, Encode, Reader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, ObjectIdentifier},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const_monty_params!(
    Tc26Order,
    U256,
    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
);
const_monty_params!(
    CpOrder,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"
);
const_monty_form!(Tc26Scalar, Tc26Order);
const_monty_form!(CpScalar, CpOrder);

// TC26 parameter Z, RFC 8891; rows from least significant nibble upward.
const SBOX: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

fn hash(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new(Vec::new());
    for part in parts {
        bytes.extend_from_slice(part);
    }
    Zeroizing::new(gost_sign_core::hash256(&bytes))
}

fn cpkdf(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    // Unicode encoding differs among source implementations; reject, never guess.
    if !password.is_ascii() || password.len() > 256 || password.contains('\0') {
        return Err(
            "Пароль КриптоПро пока поддерживает только ASCII, до 256 байт, без нулевого байта"
                .into(),
        );
    }
    let mut pin = Zeroizing::new(vec![0u8; password.len() * 4]);
    for (i, b) in password.bytes().enumerate() {
        pin[i * 4] = b;
    }
    let initial = hash(&[salt, &pin]);
    let mut c = Zeroizing::new([0u8; 64]);
    let label = b"DENEFH028.760246785.IUEFHWUIO.EF";
    c[..label.len()].copy_from_slice(label);
    let mut inner = Zeroizing::new([0u8; 64]);
    let mut outer = Zeroizing::new([0u8; 64]);
    for _ in 0..if password.is_empty() { 2 } else { 2000 } {
        for i in 0..64 {
            inner[i] = c[i] ^ 0x36;
            outer[i] = c[i] ^ 0x5c;
        }
        c[..32].copy_from_slice(&*hash(&[&*inner, &*initial, &*outer, &*initial]));
        c[32..].fill(0);
    }
    for i in 0..64 {
        inner[i] = c[i] ^ 0x36;
        outer[i] = c[i] ^ 0x5c;
    }
    let intermediate = hash(&[&inner[..32], salt, &outer[..32], &pin]);
    Ok(hash(&[&*intermediate]))
}

// Legacy 16-round MAC, not CMAC. Uses constant-time selection of the S-box row.
fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 4] {
    let mut state = [0u8; 8];
    for chunk in message.chunks(8) {
        for (i, b) in chunk.iter().enumerate() {
            state[i] ^= b;
        }
        let mut left = u32::from_le_bytes(state[..4].try_into().expect("fixed"));
        let mut right = u32::from_le_bytes(state[4..].try_into().expect("fixed"));
        for round in 0..16 {
            let offset = (round % 8) * 4;
            let word = u32::from_le_bytes(key[offset..offset + 4].try_into().expect("fixed"));
            let value = left.wrapping_add(word);
            let mut substituted = 0u32;
            for (row, table) in SBOX.iter().enumerate() {
                let nibble = ((value >> (row * 4)) & 15) as u8;
                let mut selected = 0u8;
                for (index, entry) in table.iter().enumerate() {
                    selected |=
                        entry & (0u8.wrapping_sub(nibble.ct_eq(&(index as u8)).unwrap_u8()));
                }
                substituted |= u32::from(selected) << (row * 4);
            }
            (left, right) = (right ^ substituted.rotate_left(11), left);
        }
        state[..4].copy_from_slice(&left.to_le_bytes());
        state[4..].copy_from_slice(&right.to_le_bytes());
    }
    state[..4].try_into().expect("fixed")
}

fn fields(input: &[u8]) -> Result<Vec<AnyRef<'_>>> {
    Ok(
        AnyRef::from_der(input)?.sequence(|reader| -> der::Result<_> {
            let mut result = Vec::new();
            while !reader.is_finished() {
                result.push(reader.decode()?);
            }
            Ok(result)
        })?,
    )
}
fn tagged<'a>(items: &[AnyRef<'a>], tag: Tag) -> Result<AnyRef<'a>> {
    let mut found = items.iter().filter(|item| item.tag() == tag);
    let value = *found
        .next()
        .ok_or("Отсутствует обязательное поле контейнера")?;
    if found.next().is_some() {
        return Err("Повторяется поле контейнера".into());
    }
    Ok(value)
}
fn wrap(tag: Tag, content: &[u8]) -> Result<Vec<u8>> {
    Ok(AnyRef::new(tag, content)?.to_der()?)
}

fn password_matches(password: &str, fingerprint: &[u8], stored: &[u8]) -> Result<bool> {
    if stored.len() != 4 {
        return Err("Неподдерживаемая длина кода проверки пароля".into());
    }
    // CSP also writes an all-zero verifier for containers without a password.
    // This marker accepts only the empty password; mask integrity and full
    // key/certificate binding must still be verified during import.
    if bool::from(stored.ct_eq(&[0; 4])) {
        return Ok(password.is_empty());
    }
    let key = cpkdf(password, fingerprint)?;
    Ok(bool::from(mac(&key, &[0; 16]).ct_eq(stored)))
}

impl Container {
    /// Offline metadata check, not a token login attempt. Verifies header MAC first.
    pub fn source_password_required(&self) -> Result<bool> {
        let header = fields(&self.records[2])?;
        let content_der = header[0].to_der()?;
        if !bool::from(mac(&[0; 32], &content_der).ct_eq(header[1].value())) {
            return Err("Не совпадает контрольный код контейнера".into());
        }
        let content = fields(&content_der)?;
        let fingerprint = tagged(&content, TagNumber(10).context_specific(false))?;
        let password_mac = tagged(&content, TagNumber(2).context_specific(false))?;
        Ok(!password_matches(
            "",
            fingerprint.value(),
            password_mac.value(),
        )?)
    }

    /// Decode the primary key into PKCS#8 after password and metadata MAC checks.
    /// The result must be bound to the full certificate public key by the signer.
    /// Does not use the experimental variable-time EC verification code on secrets.
    pub fn primary_pkcs8(&self, password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let header = fields(&self.records[2])?;
        let content_der = header[0].to_der()?;
        if !bool::from(mac(&[0; 32], &content_der).ct_eq(header[1].value())) {
            return Err("Не совпадает контрольный код контейнера".into());
        }
        let content = fields(&content_der)?;
        let fingerprint = tagged(&content, TagNumber(10).context_specific(false))?;
        let password_mac = tagged(&content, TagNumber(2).context_specific(false))?;
        if !password_matches(password, fingerprint.value(), password_mac.value())? {
            return Err(
                "Неверный пароль исходного контейнера или повреждены данные проверки пароля".into(),
            );
        }
        let masks = fields(&self.records[0])?;
        let mask: &[u8; 32] = masks[0].value().try_into()?;
        if !bool::from(mac(mask, masks[1].value()).ct_eq(masks[2].value())) {
            return Err("Не совпадает контрольный код маски ключа".into());
        }
        let primary = fields(&self.records[1])?;
        let derived = cpkdf(password, masks[1].value())?;
        let cipher = gost_crypto::Gost28147::with_sbox(&derived, &SBOX);
        let mut masked = Zeroizing::new([0u8; 32]);
        for (destination, block) in masked
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(primary[0].value().as_chunks::<8>().0.iter())
        {
            destination.copy_from_slice(&cipher.decrypt_block_raw(*block));
        }
        let parameters = tagged(&content, Tag::Sequence)?;
        let parameters_der = parameters.to_der()?;
        let key_parameters = fields(&parameters_der)?;
        let algorithm = tagged(&key_parameters, TagNumber(0).context_specific(true))?;
        let algorithm_der = wrap(Tag::Sequence, algorithm.value())?;
        let algorithm_fields = fields(&algorithm_der)?;
        if algorithm_fields.len() != 2 {
            return Err("Неподдерживаемые параметры алгоритма ключа".into());
        }
        let algorithm_oid = algorithm_fields[0]
            .decode_as::<ObjectIdentifier>()?
            .to_string();
        if !matches!(
            algorithm_oid.as_str(),
            "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.6.1"
        ) {
            return Err("Неподдерживаемый алгоритм закрытого ключа".into());
        }
        let param_der = algorithm_fields[1].to_der()?;
        let params = fields(&param_der)?;
        let curve = params
            .first()
            .ok_or("Не указана эллиптическая кривая")?
            .decode_as::<ObjectIdentifier>()?
            .to_string();
        let raw = U256::from_le_slice(&*masked);
        let mask = U256::from_le_slice(mask);
        let scalar = match curve.as_str() {
            "1.2.643.7.1.2.1.1.1" => (Tc26Scalar::new(&raw)
                * Option::<Tc26Scalar>::from(Tc26Scalar::new(&mask).invert())
                    .ok_or("Недопустимая маска ключа")?)
            .retrieve(),
            "1.2.643.2.2.35.1" | "1.2.643.2.2.36.0" | "1.2.643.7.1.2.1.1.2" => {
                (CpScalar::new(&raw)
                    * Option::<CpScalar>::from(CpScalar::new(&mask).invert())
                        .ok_or("Недопустимая маска ключа")?)
                .retrieve()
            }
            _ => return Err("Неподдерживаемая эллиптическая кривая".into()),
        };
        if scalar == U256::ZERO {
            return Err("Закрытый ключ равен нулю".into());
        }
        let mut alg = ObjectIdentifier::new("1.2.643.7.1.1.1.1")?.to_der()?;
        alg.extend(param_der);
        let mut pkcs8 = Zeroizing::new(vec![2, 1, 0]);
        pkcs8.extend(wrap(Tag::Sequence, &alg)?);
        pkcs8.extend(wrap(Tag::OctetString, &scalar.to_le_bytes())?);
        Ok(Zeroizing::new(wrap(Tag::Sequence, &pkcs8)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header_container(verifier: &[u8], fingerprint: &[u8]) -> Container {
        let mut content =
            wrap(TagNumber(2).context_specific(false), verifier).expect("valid test fixture");
        content.extend(
            wrap(TagNumber(10).context_specific(false), fingerprint).expect("valid test fixture"),
        );
        let mut header = wrap(Tag::Sequence, &content).expect("valid test fixture");
        let checksum = mac(&[0; 32], &header);
        header.extend(wrap(Tag::OctetString, &checksum).expect("valid test fixture"));
        Container {
            records: vec![
                Zeroizing::new(vec![]),
                Zeroizing::new(vec![]),
                Zeroizing::new(wrap(Tag::Sequence, &header).expect("valid test fixture")),
            ],
        }
    }
    #[test]
    fn password_detection_accepts_both_empty_password_profiles() {
        let fingerprint = [7; 8];
        let computed = mac(
            &cpkdf("", &fingerprint).expect("valid test fixture"),
            &[0; 16],
        );
        for verifier in [[0; 4], computed] {
            let container = header_container(&verifier, &fingerprint);
            assert!(
                !container
                    .source_password_required()
                    .expect("valid test fixture")
            );
            assert!(password_matches("", &fingerprint, &verifier).expect("valid test fixture"));
            assert!(
                !password_matches("wrong", &fingerprint, &verifier).expect("valid test fixture")
            );
        }
        let protected = mac(
            &cpkdf("test-password", &fingerprint).expect("valid test fixture"),
            &[0; 16],
        );
        assert!(
            header_container(&protected, &fingerprint)
                .source_password_required()
                .expect("valid test fixture")
        );
        assert!(
            password_matches("test-password", &fingerprint, &protected)
                .expect("valid test fixture")
        );
        assert!(!password_matches("", &fingerprint, &protected).expect("valid test fixture"));
        assert!(password_matches("", &fingerprint, &[0; 3]).is_err());
    }
    #[test]
    fn empty_password_marker_does_not_bypass_header_integrity() {
        let mut container = header_container(&[0; 4], &[7; 8]);
        let header = &mut container.records[2];
        *header.last_mut().expect("valid test fixture") ^= 1;
        assert!(container.source_password_required().is_err());
        assert!(container.primary_pkcs8("").is_err());
    }
    #[test]
    fn published_cpkdf_vector() {
        let salt = [
            0x98, 0xe4, 0xf4, 0x94, 0x15, 0x55, 0x5d, 0x8a, 0xb2, 0x05, 0x67, 0xa0,
        ];
        let expected = [
            0xb5, 0x51, 0xb3, 0x96, 0x08, 0x78, 0x73, 0x99, 0xba, 0x85, 0xc5, 0x9c, 0x68, 0x90,
            0x6b, 0x8f, 0x83, 0xc2, 0x89, 0xcc, 0xee, 0x3c, 0x61, 0x41, 0x70, 0x0d, 0xfc, 0x75,
            0xec, 0x0f, 0xd9, 0xf5,
        ];
        assert_eq!(*cpkdf("qawsqaws", &salt).expect("KDF"), expected);
        assert!(cpkdf("пароль", &salt).is_err());
    }
}
