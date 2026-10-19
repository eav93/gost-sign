//! Standard PFX packaging using p12-keystore/RustCrypto; no OpenSSL.
//! Parsing is not a proof of key/certificate matching or certificate trust.
use der::Decode;
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, LocalKeyId, MacAlgorithm,
    Pkcs12Archive, PrivateKey, PrivateKeyChain,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MAX_SIZE: usize = 4 * 1024 * 1024;

/// Imported secret material. No Debug/Clone implementation on this wrapper.
/// Upstream private-key buffers are not guaranteed to be zeroized on drop.
pub struct KeyMaterial {
    key: PrivateKey,
    certificate: Certificate,
}
impl KeyMaterial {
    /// Exposes the PKCS#8 only to the caller that must import it into a signer.
    pub fn pkcs8_der(&self) -> &[u8] {
        self.key.as_der()
    }
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_der()
    }
}

fn check_password(password: &str) -> Result<()> {
    if password.is_empty() || password.contains('\0') || password.len() > 1024 {
        return Err(
            "Требуется непустой пароль PFX в UTF-8, не более 1024 байт, без нулевого байта".into(),
        );
    }
    Ok(())
}

/// Packages exactly one PKCS#8 and certificate. Caller must verify they match.
/// Uses fresh random salts/IV, PBKDF2-SHA256/AES256-CBC and SHA256 MAC.
pub fn export(pkcs8: &[u8], certificate: &[u8], password: &str) -> Result<Vec<u8>> {
    check_password(password)?;
    if pkcs8.len() > MAX_SIZE || certificate.len() > MAX_SIZE {
        return Err("Входные данные превышают допустимый размер".into());
    }
    gost_sign_core::parse_certificate_der(certificate)?;
    let key = PrivateKey::from_der(pkcs8)?;
    let cert = Certificate::from_der(certificate)?;
    let id = LocalKeyId::from(gost_sign_core::hash256(certificate).as_slice());
    let mut store = KeyStore::new();
    store.add_entry(
        "signing-key",
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(id, key, [cert])),
    );
    Ok(store
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .encryption_iterations(100_000)
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .mac_iterations(100_000)
        .write()?)
}

/// Reads a single-identity standard PFX. Requires MAC and matching localKeyId.
/// The signer must subsequently prove that the private key matches the certificate.
/// Proprietary CryptoPro .80 PBE and legacy RC2/3DES are deliberately unsupported.
pub fn import(pfx: &[u8], password: &str) -> Result<KeyMaterial> {
    check_password(password)?;
    if pfx.len() > MAX_SIZE {
        return Err("Размер PFX превышает допустимый предел".into());
    }
    let envelope = pkcs12::pfx::Pfx::from_der(pfx)?;
    if envelope.mac_data.is_none() {
        return Err("PFX без контрольного кода не поддерживается".into());
    }
    let mut archive = Pkcs12Archive::from_pkcs12(pfx, password)?;
    if archive.keys.len() != 1 || archive.certs.len() != 1 || !archive.secrets.is_empty() {
        return Err("Ожидается ровно один ключ и один сертификат".into());
    }
    let key = archive.keys.pop().ok_or("Отсутствует закрытый ключ")?;
    let cert = archive.certs.pop().ok_or("Отсутствует сертификат")?;
    if key.local_key_id.as_ref().map(|id| &id.0) != cert.local_key_id.as_ref()
        || key.local_key_id.is_none()
    {
        return Err("Идентификаторы ключа и сертификата не совпадают".into());
    }
    gost_sign_core::parse_certificate_der(cert.cert.as_der())?;
    Ok(KeyMaterial {
        key: key.key,
        certificate: cert.cert,
    })
}
