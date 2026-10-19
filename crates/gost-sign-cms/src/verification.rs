//! Strict detached CMS verification for the supported single-signer GOST 2012-256 profile.
//! Mathematical verification only; no certificate trust, expiry, revocation or key-usage policy.
use super::*;
use gost_sign_core::verification::{
    VerificationError as CoreError, verify_data_signature_gost2012_256,
};

const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Failure to parse or support a CMS structure, distinct from a cryptographic mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    Malformed,
    Unsupported,
}
impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed CMS or certificate encoding",
            Self::Unsupported => "unsupported CMS signature profile",
        })
    }
}
impl std::error::Error for VerificationError {}
impl From<der::Error> for VerificationError {
    fn from(_: der::Error) -> Self {
        Self::Malformed
    }
}

fn single_value(attrs: &Attributes, oid: ObjectIdentifier) -> Result<&Any, VerificationError> {
    let attribute = attrs
        .iter()
        .find(|a| a.oid == oid)
        .ok_or(VerificationError::Malformed)?;
    if attribute.values.len() != 1 {
        return Err(VerificationError::Malformed);
    }
    attribute
        .values
        .iter()
        .next()
        .ok_or(VerificationError::Malformed)
}

/// Verify exact detached content and the CMS signed attributes against its included certificate.
///
/// `Ok(true)` means the content digest, certificate binding and mathematical signature
/// match. It does **not** establish certificate trust, validity dates, revocation, signing
/// authority, or qualified-signature status. The ECC verifier is experimental.
///
/// This deliberately narrow profile requires DER, one signer and one included public
/// certificate, issuer/serial SID, Streebog-256, a supported GOST 2012-256 curve, and SigningCertificateV2
/// with one GOST certificate reference including issuerSerial. Optional signingTime is
/// accepted and syntax-checked; other attributes, CRLs and unsigned attributes are unsupported.
/// No authenticated meaning or trusted time is inferred from signingTime.
///
/// A well-formed signature, content digest or certificate binding mismatch yields `Ok(false)`.
/// Malformed data and unsupported profiles yield distinct errors.
pub fn verify_detached(content: &[u8], cms_der: &[u8]) -> Result<bool, VerificationError> {
    use VerificationError as E;
    let envelope = ContentInfo::from_der(cms_der)?;
    if envelope.content_type != SIGNED_DATA {
        return Err(E::Unsupported);
    }
    if envelope.to_der()? != cms_der {
        return Err(E::Malformed);
    }
    let signed: SignedData = envelope.content.decode_as()?;
    if signed.to_der()? != envelope.content.to_der()? {
        return Err(E::Malformed);
    }
    if signed.version != CmsVersion::V1
        || signed.encap_content_info.econtent_type != DATA
        || signed.encap_content_info.econtent.is_some()
        || signed.crls.is_some()
        || signed.signer_infos.0.len() != 1
        || signed.digest_algorithms.len() != 1
    {
        return Err(E::Unsupported);
    }
    let digest_algorithm = signed.digest_algorithms.iter().next().ok_or(E::Malformed)?;
    if *digest_algorithm != algorithm(GOST_HASH) {
        return Err(E::Unsupported);
    }
    let certificates = signed.certificates.as_ref().ok_or(E::Malformed)?;
    if certificates.0.len() != 1 {
        return Err(E::Unsupported);
    }
    let CertificateChoices::Certificate(certificate) =
        certificates.0.iter().next().ok_or(E::Malformed)?
    else {
        return Err(E::Unsupported);
    };
    let signer = signed.signer_infos.0.iter().next().ok_or(E::Malformed)?;
    if signer.version != CmsVersion::V1
        || signer.digest_alg != algorithm(GOST_HASH)
        || signer.signature_algorithm != algorithm(GOST_KEY)
        || signer.unsigned_attrs.is_some()
    {
        return Err(E::Unsupported);
    }
    if signer.signature.as_bytes().len() != 64 {
        return Err(E::Malformed);
    }
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &signer.sid else {
        return Err(E::Unsupported);
    };
    let tbs = certificate.tbs_certificate();
    let sid_matches = sid.issuer == *tbs.issuer() && sid.serial_number == *tbs.serial_number();
    let attrs = signer.signed_attrs.as_ref().ok_or(E::Malformed)?;
    let mut seen = std::collections::BTreeSet::new();
    for attribute in attrs.iter() {
        if !seen.insert(attribute.oid) || attribute.values.len() != 1 {
            return Err(E::Malformed);
        }
        if ![CONTENT_TYPE, MESSAGE_DIGEST, SIGNING_CERT_V2, SIGNING_TIME].contains(&attribute.oid) {
            return Err(E::Unsupported);
        }
        if attribute.oid == SIGNING_TIME {
            let _: x509_cert::time::Time = single_value(attrs, SIGNING_TIME)?.decode_as()?;
        }
    }
    let content_type: ObjectIdentifier = single_value(attrs, CONTENT_TYPE)?.decode_as()?;
    if content_type != DATA {
        return Err(E::Unsupported);
    }
    let digest: OctetString = single_value(attrs, MESSAGE_DIGEST)?.decode_as()?;
    if digest.as_bytes().len() != 32 {
        return Err(E::Malformed);
    }
    let binding: SigningCertificateV2 = single_value(attrs, SIGNING_CERT_V2)?.decode_as()?;
    if binding.certs.len() != 1 {
        return Err(E::Unsupported);
    }
    let reference = binding.certs.first().ok_or(E::Malformed)?;
    if reference.hash_algorithm != algorithm(GOST_HASH) {
        return Err(E::Unsupported);
    }
    if reference.cert_hash.as_bytes().len() != 32 || reference.issuer_serial.issuer.len() != 1 {
        return Err(E::Malformed);
    }
    let [GeneralName::DirectoryName(issuer)] = reference.issuer_serial.issuer.as_slice() else {
        return Err(E::Unsupported);
    };
    let certificate_der = certificate.to_der()?;
    // Validate the certificate profile and signature encoding even when content differs.
    let signature_valid = verify_data_signature_gost2012_256(
        &attrs.to_der()?,
        &certificate_der,
        signer.signature.as_bytes(),
    )
    .map_err(|e| match e {
        CoreError::InvalidDer | CoreError::InvalidEncoding => E::Malformed,
        CoreError::AlgorithmMismatch
        | CoreError::UnsupportedAlgorithm
        | CoreError::UnsupportedParameters => E::Unsupported,
    })?;
    Ok(sid_matches
        && digest.as_bytes() == gost_sign_core::hash256(content)
        && reference.cert_hash.as_bytes() == gost_sign_core::hash256(&certificate_der)
        && issuer == tbs.issuer()
        && reference.issuer_serial.serial_number == *tbs.serial_number()
        && signature_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    const SYNTHETIC_CERTIFICATE: &[u8] = &hex!(
        "3081e5308193020101300a06082a850307010103023000301e170d3236303130313030303030305a170d3237303130313030303030305a3000305e301706082a85030701010101300b06092a8503070102010101034300044000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300a06082a8503070101030203410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    fn sample() -> Vec<u8> {
        PreparedDetachedSignature::new(b"payload", SYNTHETIC_CERTIFICATE)
            .expect("synthetic cert")
            .finish(&[0; 64])
            .expect("CMS")
    }
    fn mutate(mutator: impl FnOnce(&mut SignedData)) -> Vec<u8> {
        let mut envelope = ContentInfo::from_der(&sample()).expect("envelope");
        let mut signed: SignedData = envelope.content.decode_as().expect("signed data");
        mutator(&mut signed);
        envelope.content = Any::encode_from(&signed).expect("encode signed data");
        envelope.to_der().expect("encode envelope")
    }
    fn alter_attrs(signed: &mut SignedData, alter: impl FnOnce(&mut Vec<Attribute>)) {
        let mut signer = signed.signer_infos.0.iter().next().expect("signer").clone();
        let mut attrs: Vec<Attribute> = signer
            .signed_attrs
            .as_ref()
            .expect("attrs")
            .iter()
            .cloned()
            .collect();
        alter(&mut attrs);
        signer.signed_attrs = Some(Attributes::try_from(attrs).expect("attributes"));
        signed.signer_infos = SetOfVec::try_from(vec![signer]).expect("signers").into();
    }
    #[test]
    fn structural_cms_with_dummy_signature_is_not_accepted() {
        assert_eq!(verify_detached(b"payload", &sample()), Ok(false));
        assert_eq!(verify_detached(b"different content", &sample()), Ok(false));
    }
    #[test]
    fn missing_digest_is_malformed_and_wrong_digest_is_mismatch() {
        let missing = mutate(|s| alter_attrs(s, |attrs| attrs.retain(|a| a.oid != MESSAGE_DIGEST)));
        assert_eq!(
            verify_detached(b"payload", &missing),
            Err(VerificationError::Malformed)
        );
        let wrong = mutate(|s| {
            alter_attrs(s, |attrs| {
                let a = attrs
                    .iter_mut()
                    .find(|a| a.oid == MESSAGE_DIGEST)
                    .expect("digest");
                a.values = SetOfVec::try_from(vec![
                    Any::encode_from(&OctetString::new([42; 32]).expect("octets"))
                        .expect("digest DER"),
                ])
                .expect("values");
            })
        });
        assert_eq!(verify_detached(b"payload", &wrong), Ok(false));
    }
    #[test]
    fn duplicate_attribute_oids_and_unknown_attributes_are_rejected() {
        let duplicate = mutate(|s| {
            alter_attrs(s, |attrs| {
                attrs.push(
                    attr(
                        MESSAGE_DIGEST,
                        Any::encode_from(&OctetString::new([42; 32]).expect("octets"))
                            .expect("DER"),
                    )
                    .expect("attr"),
                );
            })
        });
        assert_eq!(
            verify_detached(b"payload", &duplicate),
            Err(VerificationError::Malformed)
        );
        let unknown = mutate(|s| {
            alter_attrs(s, |attrs| {
                attrs.push(
                    attr(
                        ObjectIdentifier::new_unwrap("1.2.3.4"),
                        Any::encode_from(&DATA).expect("DER"),
                    )
                    .expect("attr"),
                );
            })
        });
        assert_eq!(
            verify_detached(b"payload", &unknown),
            Err(VerificationError::Unsupported)
        );
    }
    #[test]
    fn rejects_encapsulated_content_and_malformed_input() {
        let attached = mutate(|s| {
            s.encap_content_info.econtent = Some(
                Any::encode_from(&OctetString::new(b"payload".as_slice()).expect("octets"))
                    .expect("DER"),
            )
        });
        assert_eq!(
            verify_detached(b"payload", &attached),
            Err(VerificationError::Unsupported)
        );
        let cms = sample();
        for end in 0..cms.len() {
            assert_eq!(
                verify_detached(b"payload", &cms[..end]),
                Err(VerificationError::Malformed)
            );
        }
        let mut trailing = cms;
        trailing.push(0);
        assert_eq!(
            verify_detached(b"payload", &trailing),
            Err(VerificationError::Malformed)
        );
    }
}
