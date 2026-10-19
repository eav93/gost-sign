//! Portable GOST 2012-256 signing. No OpenSSL or CryptoPro runtime.
//! The local curve adapter is not independently audited. Certificate binding
//! is mathematical only; certificate trust/expiry/revocation are caller policy.
mod arithmetic;
use der::{Decode, Encode};
use gost_sign_core::verification::{Gost256Curve, decode_gost2012_256_public_key};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
#[derive(Debug)]
pub struct Error(pub(crate) &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Generate a 32-character ASCII password with 192 bits of OS randomness.
/// Does not print or persist the password; callers own its presentation/storage.
pub fn generate_pfx_password() -> Result<Zeroizing<String>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::fill(random.as_mut())
        .map_err(|_| Error("Не удалось получить случайные данные ОС"))?;
    let mut password = Zeroizing::new(String::with_capacity(32));
    // 256 is divisible by 64: the mapping has no modulo bias.
    for byte in random.iter() {
        password.push(char::from(ALPHABET[usize::from(byte & 63)]));
    }
    Ok(password)
}

/// Owns a validated key and its certificate. No Debug/Clone/secret accessors.
pub struct SigningIdentity {
    key: Zeroizing<[u8; 32]>,
    pkcs8: Zeroizing<Vec<u8>>,
    certificate: Vec<u8>,
    curve: Gost256Curve,
}
impl SigningIdentity {
    pub fn import_pkcs8(certificate: &[u8], pkcs8: &[u8]) -> Result<Self> {
        if certificate.len() > 4 * 1024 * 1024 || pkcs8.len() > 16384 {
            return Err(Error("Слишком большой сертификат или ключ"));
        }
        let info =
            pkcs8::PrivateKeyInfoRef::from_der(pkcs8).map_err(|_| Error("Некорректный PKCS#8"))?;
        let cert = gost_sign_core::parse_certificate_der(certificate)
            .map_err(|_| Error("Некорректный сертификат"))?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        if info
            .algorithm
            .to_der()
            .map_err(|_| Error("Некорректный алгоритм ключа"))?
            != spki
                .algorithm
                .to_der()
                .map_err(|_| Error("Некорректный алгоритм сертификата"))?
            || info.public_key.is_some()
        {
            return Err(Error(
                "Параметры закрытого ключа и сертификата не совпадают",
            ));
        }
        let key = Zeroizing::new(
            info.private_key
                .as_bytes()
                .try_into()
                .map_err(|_| Error("Требуется 32-байтовый закрытый ключ ГОСТ 2012-256"))?,
        );
        let (curve, expected) = decode_gost2012_256_public_key(certificate)
            .map_err(|_| Error("Неподдерживаемые параметры сертификата"))?;
        let actual = arithmetic::public(curve, &key)?;
        if !bool::from(actual.ct_eq(&expected)) {
            return Err(Error("Закрытый ключ не соответствует сертификату"));
        }
        Ok(Self {
            key,
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
            certificate: certificate.to_vec(),
            curve,
        })
    }
    pub fn import_pkcs12(pfx: &[u8], password: &str) -> Result<Self> {
        let material = gost_sign_pfx::import(pfx, password)
            .map_err(|_| Error("Не удалось открыть PFX: проверьте пароль и формат"))?;
        Self::import_pkcs8(material.certificate_der(), material.pkcs8_der())
    }
    pub fn export_pkcs12(&self, password: &str) -> Result<Vec<u8>> {
        gost_sign_pfx::export(&self.pkcs8, &self.certificate, password)
            .map_err(|_| Error("Не удалось сохранить PFX: требуется непустой допустимый пароль"))
    }
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }
    pub fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        arithmetic::sign(self.curve, &self.key, &gost_sign_core::hash256(data))
    }
    pub fn sign_cades(&self, data: &[u8]) -> Result<Vec<u8>> {
        let prepared = gost_sign_cms::PreparedDetachedSignature::new(data, &self.certificate)
            .map_err(|_| Error("Не удалось подготовить CAdES"))?;
        let signature = self.sign(prepared.signed_attributes_der())?;
        prepared
            .finish(&signature)
            .map_err(|_| Error("Не удалось сформировать CAdES"))
    }
}
