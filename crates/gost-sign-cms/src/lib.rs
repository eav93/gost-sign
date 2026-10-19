//! Portable detached CMS/CAdES-BES structure preparation for GOST 2012-256.
//!
//! No private keys, signing, trust validation, or CryptoPro code are included.
//! An external signer must sign the exact DER SET OF returned by `signed_attributes_der`.
//! References: RFC 5652 sections 5.3–5.5; RFC 5035 section 4; RFC 5126 section 5.7.3;
//! RFC 9215 section 2 (64-byte signature: big-endian s followed by big-endian r).

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo},
};
use der::{
    Decode, Encode, Sequence,
    asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
};
use x509_cert::{
    Certificate,
    attr::{Attribute, Attributes},
    ext::pkix::name::{GeneralName, GeneralNames},
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
};

const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const GOST_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.1");
#[cfg(test)]
const TC26_256_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.2.1.1.1");
const GOST_HASH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.2.2");
// CMS uses the public-key algorithm OID, as observed in CryptoPro CAdES output.
const GOST_SIGNATURE: ObjectIdentifier = GOST_KEY;

/// Structural preparation errors. No certificate trust checks are implied.
#[derive(Debug)]
pub enum Error {
    Der(der::Error),
    UnsupportedCertificate,
    InvalidSignatureLength,
}
impl From<der::Error> for Error {
    fn from(value: der::Error) -> Self {
        Self::Der(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Der(e) => write!(f, "invalid DER: {e}"),
            Self::UnsupportedCertificate => {
                f.write_str("expected a supported GOST 2012-256 public key certificate")
            }
            Self::InvalidSignatureLength => {
                f.write_str("expected exactly 64 signature octets (s || r, big endian)")
            }
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}
// GOST is not the SHA-256 default, so hash_algorithm is always explicitly encoded.
#[derive(Clone, Debug, Sequence)]
struct EssCertIdV2 {
    hash_algorithm: AlgorithmIdentifierOwned,
    cert_hash: OctetString,
    issuer_serial: IssuerSerial,
}
#[derive(Clone, Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

fn algorithm(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}
fn attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute, der::Error> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}

/// Immutable binding of exact content bytes and one public signing certificate.
///
/// This is a structural CMS builder, not a signature verifier. `finish` accepts
/// an externally calculated signature; it cannot prove that signature is correct.
#[derive(Clone, Debug)]
pub struct PreparedDetachedSignature {
    certificate: Certificate,
    attributes: Attributes,
    signed_attributes_der: Vec<u8>,
}
impl PreparedDetachedSignature {
    /// Prepare the content-type, message-digest, and SigningCertificateV2 attributes.
    /// The certificate is parsed structurally and must contain a supported GOST 2012-256 key.
    /// This does not validate the curve point, certificate signature, key usage, or trust.
    pub fn new(content: &[u8], certificate_der: &[u8]) -> Result<Self, Error> {
        let certificate = Certificate::from_der(certificate_der)?;
        let tbs = certificate.tbs_certificate();
        gost_sign_core::verification::decode_gost2012_256_public_key(certificate_der)
            .map_err(|_| Error::UnsupportedCertificate)?;
        let cert_ref = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: algorithm(GOST_HASH),
                cert_hash: OctetString::new(gost_sign_core::hash256(certificate_der))?,
                issuer_serial: IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(tbs.issuer().clone())],
                    serial_number: tbs.serial_number().clone(),
                },
            }],
        };
        let attributes = Attributes::try_from(vec![
            attr(CONTENT_TYPE, Any::encode_from(&DATA)?)?,
            attr(
                MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(gost_sign_core::hash256(content))?)?,
            )?,
            attr(SIGNING_CERT_V2, Any::encode_from(&cert_ref)?)?,
        ])?;
        let signed_attributes_der = attributes.to_der()?;
        Ok(Self {
            certificate,
            attributes,
            signed_attributes_der,
        })
    }

    /// Exact bytes to hash and sign: DER SET OF, tag 0x31 (never the CMS [0] tag).
    #[must_use]
    pub fn signed_attributes_der(&self) -> &[u8] {
        &self.signed_attributes_der
    }

    /// Streebog-256 of `signed_attributes_der`, for external prehash signers.
    /// Do not hash this digest again when using a prehash signing interface.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        gost_sign_core::hash256(self.signed_attributes_der())
    }

    /// Package a 64-byte external GOST signature, unmodified, into detached CMS.
    /// Signature representation must be big-endian s || r. No byte reversal or
    /// cryptographic signature verification is performed. The certificate is included.
    pub fn finish(&self, signature: &[u8]) -> Result<Vec<u8>, Error> {
        if signature.len() != 64 {
            return Err(Error::InvalidSignatureLength);
        }
        let tbs = self.certificate.tbs_certificate();
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: tbs.issuer().clone(),
                serial_number: tbs.serial_number().clone(),
            }),
            digest_alg: algorithm(GOST_HASH),
            signed_attrs: Some(self.attributes.clone()),
            signature_algorithm: algorithm(GOST_SIGNATURE),
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };
        let signed = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![algorithm(GOST_HASH)])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: DATA,
                econtent: None,
            },
            certificates: Some(
                SetOfVec::try_from(vec![CertificateChoices::Certificate(
                    self.certificate.clone(),
                )])?
                .into(),
            ),
            crls: None,
            signer_infos: SetOfVec::try_from(vec![signer])?.into(),
        };
        Ok(ContentInfo {
            content_type: SIGNED_DATA,
            content: Any::encode_from(&signed)?,
        }
        .to_der()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    // Structurally valid unsigned synthetic certificate; no private identity.
    const SYNTHETIC_CERTIFICATE: &[u8] = &hex!(
        "3081e5308193020101300a06082a850307010103023000301e170d3236303130313030303030305a170d3237303130313030303030305a3000305e301706082a85030701010101300b06092a8503070102010101034300044000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300a06082a8503070101030203410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    fn prepared(content: &[u8]) -> PreparedDetachedSignature {
        PreparedDetachedSignature::new(content, SYNTHETIC_CERTIFICATE)
            .expect("synthetic certificate")
    }
    fn attribute_value(prepared: &PreparedDetachedSignature, oid: ObjectIdentifier) -> Any {
        prepared
            .attributes
            .iter()
            .find(|a| a.oid == oid)
            .expect("attribute")
            .values
            .iter()
            .next()
            .expect("single value")
            .clone()
    }
    #[test]
    fn exact_signing_input_is_der_set_not_context_tag() {
        let prepared = prepared(b"exact bytes\r\n");
        let der = prepared.signed_attributes_der();
        assert_eq!(der[0], 0x31);
        assert_eq!(
            Attributes::from_der(der).expect("DER SET"),
            prepared.attributes
        );
        assert_eq!(prepared.signing_digest(), gost_sign_core::hash256(der));
        let mut context = der.to_vec();
        context[0] = 0xa0;
        assert_ne!(prepared.signing_digest(), gost_sign_core::hash256(&context));
    }
    #[test]
    fn attributes_bind_exact_content_and_full_certificate_and_issuer_serial() {
        let p = prepared(b"payload\0");
        let md = OctetString::from_der(&attribute_value(&p, MESSAGE_DIGEST).to_der().expect("DER"))
            .expect("digest");
        assert_eq!(md.as_bytes(), gost_sign_core::hash256(b"payload\0"));
        assert_ne!(p.signing_digest(), prepared(b"payload").signing_digest());
        assert_eq!(
            ObjectIdentifier::from_der(&attribute_value(&p, CONTENT_TYPE).to_der().expect("DER"))
                .expect("OID"),
            DATA
        );
        let binding = SigningCertificateV2::from_der(
            &attribute_value(&p, SIGNING_CERT_V2).to_der().expect("DER"),
        )
        .expect("ESS");
        assert_eq!(binding.certs.len(), 1);
        assert_eq!(
            binding.certs[0].cert_hash.as_bytes(),
            gost_sign_core::hash256(SYNTHETIC_CERTIFICATE)
        );
        assert_eq!(binding.certs[0].hash_algorithm.oid, GOST_HASH);
        assert!(binding.certs[0].hash_algorithm.parameters.is_none());
        assert_eq!(
            binding.certs[0].issuer_serial.issuer,
            vec![GeneralName::DirectoryName(
                p.certificate.tbs_certificate().issuer().clone()
            )]
        );
        assert_eq!(
            &binding.certs[0].issuer_serial.serial_number,
            p.certificate.tbs_certificate().serial_number()
        );
        let mut changed_certificate = SYNTHETIC_CERTIFICATE.to_vec();
        *changed_certificate.last_mut().expect("signature octet") ^= 1;
        let changed = PreparedDetachedSignature::new(b"payload\0", &changed_certificate)
            .expect("structural certificate");
        assert_ne!(p.signing_digest(), changed.signing_digest());
    }
    #[test]
    fn detached_cms_preserves_signature_and_all_signed_attributes() {
        let p = prepared(b"detached document");
        let signature: Vec<u8> = (0..64).collect();
        let output = p.finish(&signature).expect("CMS");
        let envelope = ContentInfo::from_der(&output).expect("ContentInfo");
        assert_eq!(envelope.content_type, SIGNED_DATA);
        let signed =
            SignedData::from_der(&envelope.content.to_der().expect("DER")).expect("SignedData");
        assert_eq!(signed.version, CmsVersion::V1);
        assert!(signed.encap_content_info.econtent.is_none());
        assert_eq!(signed.encap_content_info.econtent_type, DATA);
        assert_eq!(signed.certificates.expect("included cert").0.len(), 1);
        let signer = signed.signer_infos.0.iter().next().expect("signer");
        assert_eq!(signer.signature.as_bytes(), signature);
        assert_eq!(signer.signature_algorithm.oid, GOST_SIGNATURE);
        assert!(signer.signature_algorithm.parameters.is_none());
        assert_eq!(signer.digest_alg.oid, GOST_HASH);
        assert_eq!(
            signer
                .signed_attrs
                .as_ref()
                .expect("attributes")
                .to_der()
                .expect("DER"),
            p.signed_attributes_der()
        );
        let mut implicit = p.signed_attributes_der().to_vec();
        implicit[0] = 0xa0;
        assert!(
            signer
                .to_der()
                .expect("signer DER")
                .windows(implicit.len())
                .any(|w| w == implicit)
        );
    }
    #[test]
    fn rejects_wrong_signature_lengths_and_malformed_or_unsupported_certificates() {
        for len in [0, 1, 32, 63, 65, 128] {
            assert!(matches!(
                prepared(b"").finish(&vec![0; len]),
                Err(Error::InvalidSignatureLength)
            ));
        }
        assert!(PreparedDetachedSignature::new(b"", b"not DER").is_err());
        for end in 0..SYNTHETIC_CERTIFICATE.len() {
            assert!(PreparedDetachedSignature::new(b"", &SYNTHETIC_CERTIFICATE[..end]).is_err());
        }
        let mut unsupported = SYNTHETIC_CERTIFICATE.to_vec();
        let oid = GOST_KEY.to_der().expect("OID DER");
        let index = unsupported
            .windows(oid.len())
            .position(|w| w == oid)
            .expect("key OID");
        unsupported[index + oid.len() - 1] = 2; // 512-bit key algorithm is outside this profile.
        assert!(matches!(
            PreparedDetachedSignature::new(b"", &unsupported),
            Err(Error::UnsupportedCertificate)
        ));
        let mut unsupported_curve = SYNTHETIC_CERTIFICATE.to_vec();
        let oid = TC26_256_A.to_der().expect("curve OID DER");
        let index = unsupported_curve
            .windows(oid.len())
            .position(|w| w == oid)
            .expect("curve OID");
        unsupported_curve[index + oid.len() - 1] = 99;
        assert!(matches!(
            PreparedDetachedSignature::new(b"", &unsupported_curve),
            Err(Error::UnsupportedCertificate)
        ));
        let mut trailing = SYNTHETIC_CERTIFICATE.to_vec();
        trailing.push(0);
        assert!(PreparedDetachedSignature::new(b"", &trailing).is_err());
    }
}

pub mod verification;
