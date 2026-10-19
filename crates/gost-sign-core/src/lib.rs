//! Independent, portable building blocks for GOST signing interoperability.
//!
//! Hashes byte strings, inspects public certificates and verifies GOST signatures.
//! It does not implement private-key import, signing, or certificate trust validation.

use streebog::{Digest, Streebog256, Streebog512};
use x509_cert::der::Decode;

/// Hash exact input bytes with GOST R 34.11-2012 (256-bit Streebog).
///
/// Returns digest octets in the conventional byte-stream order, not the
/// reversed hexadecimal vector notation used in RFC 6986 examples.
#[must_use]
pub fn hash256(input: &[u8]) -> [u8; 32] {
    Streebog256::digest(input).into()
}

/// Hash exact input bytes with GOST R 34.11-2012 (512-bit Streebog).
#[must_use]
pub fn hash512(input: &[u8]) -> [u8; 64] {
    Streebog512::digest(input).into()
}

/// Decode one complete DER-encoded public X.509 certificate.
///
/// Exposes typed certificate fields, including the public-key algorithm and
/// its parameters, without platform APIs or CryptoPro. This performs structural
/// parsing only: it does **not** validate the signature, trust chain, expiry,
/// revocation status, or the suitability of the key for signing.
///
/// # Errors
/// Returns a DER parsing error for malformed input or trailing bytes.
pub fn parse_certificate_der(
    input: &[u8],
) -> Result<x509_cert::Certificate, x509_cert::der::Error> {
    x509_cert::Certificate::from_der(input)
}

pub mod verification;
