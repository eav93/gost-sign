//! Mathematical signature verification only: no trust, validity or revocation policy.
use crate::{hash256, parse_certificate_der};
use std::fmt;
use x509_cert::der::{
    Decode, Encode, Sequence,
    asn1::{ObjectIdentifier, OctetString},
};

const SIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.3.2");
const PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.1");
const DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.2.2");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidDer,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
    UnsupportedParameters,
    InvalidEncoding,
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDer => "Malformed DER certificate",
            Self::AlgorithmMismatch => "Inner and outer signature algorithms differ",
            Self::UnsupportedAlgorithm => "Unsupported signature or public-key algorithm",
            Self::UnsupportedParameters => "Unsupported GOST curve or digest parameters",
            Self::InvalidEncoding => "Invalid public-key or signature encoding",
        })
    }
}
impl std::error::Error for VerificationError {}

#[derive(Sequence)]
struct PublicKeyParameters {
    curve: ObjectIdentifier,
    digest: Option<ObjectIdentifier>,
}

/// Supported 256-bit parameter sets (RFC 9215 and RFC 4357).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gost256Curve {
    Tc26A,
    CryptoProA,
}

/// Verify a certificate signature using the supplied issuer's TC26-256-A public key.
///
/// `Ok(true)` establishes mathematical signature validity only. It does not establish
/// issuer trust, issuer-name matching, CA/key usage, certificate validity periods,
/// revocation status, qualified-signature status, or a trusted certificate chain.
/// Both inputs must be complete DER certificates. Unsupported algorithms are errors;
/// a well-formed but incorrect signature or invalid curve point returns `Ok(false)`.
/// The underlying verifier is experimental and processes public data only.
///
/// # Errors
/// Returns a [`VerificationError`] for malformed encodings or unsupported algorithms.
pub fn verify_certificate_signature_tc26_256_a(
    certificate_der: &[u8],
    issuer_der: &[u8],
) -> Result<bool, VerificationError> {
    verify_certificate(certificate_der, issuer_der, true)
}

/// Verify a GOST 2012-256 certificate signature on a supported curve.
/// Mathematical verification only: no issuer trust, names, dates or revocation checks.
pub fn verify_certificate_signature_gost2012_256(
    certificate_der: &[u8],
    issuer_der: &[u8],
) -> Result<bool, VerificationError> {
    verify_certificate(certificate_der, issuer_der, false)
}

fn verify_certificate(
    certificate_der: &[u8],
    issuer_der: &[u8],
    only_a: bool,
) -> Result<bool, VerificationError> {
    use VerificationError as E;
    let certificate = parse_certificate_der(certificate_der).map_err(|_| E::InvalidDer)?;
    let algorithm = certificate.signature_algorithm();
    if algorithm != certificate.tbs_certificate().signature() {
        return Err(E::AlgorithmMismatch);
    }
    if algorithm.oid != SIGNATURE || algorithm.parameters.is_some() {
        return Err(E::UnsupportedAlgorithm);
    }
    let signature = certificate
        .signature()
        .as_bytes()
        .ok_or(E::InvalidEncoding)?;
    if signature.len() != 64 {
        return Err(E::InvalidEncoding);
    }
    let tbs = certificate
        .tbs_certificate()
        .to_der()
        .map_err(|_| E::InvalidDer)?;
    verify_data(&tbs, issuer_der, signature, only_a)
}

/// Verify a detached raw RFC9215 signature over exact data bytes, with a certificate's key.
/// Does not establish certificate trust, validity, key usage or revocation status.
/// Only TC26-256-A is supported. Signature encoding is 64 octets s_BE || r_BE.
///
/// # Errors
/// Returns an error for malformed DER/encodings or unsupported key parameters.
pub fn verify_data_signature_tc26_256_a(
    data: &[u8],
    certificate_der: &[u8],
    signature: &[u8],
) -> Result<bool, VerificationError> {
    verify_data(data, certificate_der, signature, true)
}

/// Verify a raw s_BE || r_BE signature with a supported GOST 2012-256 certificate.
/// Mathematical verification only, without certificate trust or validity checks.
pub fn verify_data_signature_gost2012_256(
    data: &[u8],
    certificate_der: &[u8],
    signature: &[u8],
) -> Result<bool, VerificationError> {
    verify_data(data, certificate_der, signature, false)
}

fn verify_data(
    data: &[u8],
    certificate_der: &[u8],
    signature: &[u8],
    only_a: bool,
) -> Result<bool, VerificationError> {
    let (curve, public_key) = decode_gost2012_256_public_key(certificate_der)?;
    if only_a && curve != Gost256Curve::Tc26A {
        return Err(VerificationError::UnsupportedParameters);
    }
    if signature.len() != 64 {
        return Err(VerificationError::InvalidEncoding);
    }
    let digest = hash256(data);
    Ok(match curve {
        Gost256Curve::Tc26A => {
            gost_sign_experimental::verify_tc26_256_a(&digest, &public_key, signature)
        }
        Gost256Curve::CryptoProA => {
            gost_sign_experimental::verify_cryptopro_a(&digest, &public_key, signature)
        }
    })
}

/// Decode the certificate's public key and allowlisted parameter set.
/// Checks encoding and algorithm parameters only, not the curve point or certificate trust.
/// TC26-B aliases CryptoPro-A; CryptoPro-XchA uses the same curve.
pub fn decode_gost2012_256_public_key(
    certificate_der: &[u8],
) -> Result<(Gost256Curve, [u8; 64]), VerificationError> {
    use VerificationError as E;
    let issuer = parse_certificate_der(certificate_der).map_err(|_| E::InvalidDer)?;
    let spki = issuer.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != PUBLIC_KEY {
        return Err(E::UnsupportedAlgorithm);
    }
    let parameters: PublicKeyParameters = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(E::UnsupportedParameters)?
        .decode_as()
        .map_err(|_| E::UnsupportedParameters)?;
    let curve = parameter_curve(&parameters)?;
    let public_key = OctetString::from_der(
        spki.subject_public_key
            .as_bytes()
            .ok_or(E::InvalidEncoding)?,
    )
    .map_err(|_| E::InvalidEncoding)?;
    let bytes = public_key
        .as_bytes()
        .try_into()
        .map_err(|_| E::InvalidEncoding)?;
    Ok((curve, bytes))
}

fn parameter_curve(parameters: &PublicKeyParameters) -> Result<Gost256Curve, VerificationError> {
    match parameters.curve.to_string().as_str() {
        "1.2.643.7.1.2.1.1.1" if parameters.digest.is_none_or(|oid| oid == DIGEST) => {
            Ok(Gost256Curve::Tc26A)
        }
        "1.2.643.7.1.2.1.1.2" if parameters.digest.is_none() => Ok(Gost256Curve::CryptoProA),
        "1.2.643.2.2.35.1" | "1.2.643.2.2.36.0" if parameters.digest == Some(DIGEST) => {
            Ok(Gost256Curve::CryptoProA)
        }
        _ => Err(VerificationError::UnsupportedParameters),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enforce_digest_parameter_rules_for_curve_aliases() {
        let select = |curve: &str, digest| {
            parameter_curve(&PublicKeyParameters {
                curve: curve.parse().expect("OID"),
                digest,
            })
        };
        for curve in ["1.2.643.2.2.35.1", "1.2.643.2.2.36.0"] {
            assert_eq!(select(curve, Some(DIGEST)), Ok(Gost256Curve::CryptoProA));
            assert_eq!(
                select(curve, None),
                Err(VerificationError::UnsupportedParameters)
            );
        }
        assert_eq!(
            select("1.2.643.7.1.2.1.1.2", None),
            Ok(Gost256Curve::CryptoProA)
        );
        assert_eq!(
            select("1.2.643.7.1.2.1.1.2", Some(DIGEST)),
            Err(VerificationError::UnsupportedParameters)
        );
        for digest in [None, Some(DIGEST)] {
            assert_eq!(
                select("1.2.643.7.1.2.1.1.1", digest),
                Ok(Gost256Curve::Tc26A)
            );
        }
        assert_eq!(
            select("1.2.643.7.1.2.1.1.1", Some(PUBLIC_KEY)),
            Err(VerificationError::UnsupportedParameters)
        );
        assert_eq!(
            select("1.2.3.4", None),
            Err(VerificationError::UnsupportedParameters)
        );
    }
}
