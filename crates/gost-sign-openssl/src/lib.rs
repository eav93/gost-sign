//! Optional native OpenSSL GOST provider backend; no command-line subprocesses.
//!
//! The caller explicitly loads a trusted local provider module. Loading affects
//! OpenSSL's process-wide default context, but does not change configuration files.
//! Imports software PKCS#8 and PKCS#12 keys; not raw CryptoPro container directories.
use openssl::{
    error::ErrorStack,
    md::Md,
    md_ctx::MdCtx,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    provider::Provider,
    x509::X509,
};

#[derive(Debug)]
pub enum Error {
    Native(ErrorStack),
    UnsupportedCertificate,
    KeyMismatch,
    InvalidSignature,
    InvalidModulePath,
    ProviderState,
    DifferentProvider,
    IncompatibleProvider,
    InvalidDer,
    InvalidPassword,
    PasswordTooLong,
    MissingIdentity,
    EmptyExportPassword,
    Pfx(String),
}
impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        Self::Native(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pfx(_) => f.write_str("Не удалось обработать PFX: проверьте пароль, целостность файла и поддерживаемые алгоритмы"),
            Self::EmptyExportPassword => f.write_str("Для экспорта PFX требуется непустой пароль"),
            Self::IncompatibleProvider => f.write_str("Модуль ГОСТ не зарегистрирован: соберите Rust и модуль с одной версией OpenSSL"),
            Self::ProviderState => f.write_str("Не удалось получить состояние криптографического модуля"),
            Self::DifferentProvider => {
                f.write_str("В процессе уже загружен другой модуль ГОСТ")
            }
            Self::InvalidDer => f.write_str("Ожидается один полный контейнер ключа в DER"),
            Self::PasswordTooLong => f.write_str("Пароль превышает допустимую длину OpenSSL"),
            Self::InvalidPassword => f.write_str("Пароль PKCS12 не может содержать нулевой байт"),
            Self::MissingIdentity => {
                f.write_str("PKCS12 должен содержать закрытый ключ и соответствующий сертификат")
            }
            Self::Native(error) => {
                f.write_str("Ошибка криптографического модуля OpenSSL")?;
                for entry in error.errors() {write!(f,"; код 0x{:X}",entry.code())?;}
                Ok(())
            },
            Self::UnsupportedCertificate => f.write_str("Неподдерживаемый сертификат ГОСТ"),
            Self::KeyMismatch => f.write_str("Закрытый ключ не соответствует сертификату"),
            Self::InvalidSignature => f.write_str("Криптографический модуль вернул некорректную подпись"),
            Self::InvalidModulePath => {
                f.write_str("Путь к криптографическому модулю должен быть абсолютным, в UTF-8, без нулевого байта")
            }
        }
    }
}
impl std::error::Error for Error {}

/// Holds provider references for the duration of native operations.
/// This adapter is experimental; provider availability is checked at runtime.
pub struct GostProvider {
    _loaded: std::sync::Arc<LoadedProviders>,
}
struct LoadedProviders {
    _gost: Provider,
    _default: Provider,
}
// The native provider initializes process-global state. Serialize initialization
// and retain references for the process lifetime; concurrent imports must never
// race provider initialization/unload. Different module versions cannot be mixed.
type ProviderSlot = Option<(std::path::PathBuf, std::sync::Arc<LoadedProviders>)>;
static PROVIDERS: std::sync::Mutex<ProviderSlot> = std::sync::Mutex::new(None);
static LEGACY: std::sync::Mutex<Option<Provider>> = std::sync::Mutex::new(None);
impl GostProvider {
    /// Standard PFX decoded by Rust; only the signing key import uses OpenSSL.
    pub fn import_standard_pkcs12(
        &self,
        pfx_der: &[u8],
        password: &str,
    ) -> Result<SigningIdentity<'_>, Error> {
        let material =
            gost_sign_pfx::import(pfx_der, password).map_err(|e| Error::Pfx(e.to_string()))?;
        self.import_pkcs8(material.certificate_der(), material.pkcs8_der())
    }
    /// Load an explicitly selected module; never downloads or executes a CLI.
    /// One canonical module path is retained for the process lifetime.
    pub fn load(module: &std::path::Path) -> Result<Self, Error> {
        if !module.is_absolute() {
            return Err(Error::InvalidModulePath);
        }
        let module = module
            .canonicalize()
            .map_err(|_| Error::InvalidModulePath)?;
        let name = module
            .to_str()
            .filter(|s| !s.contains('\0'))
            .ok_or(Error::InvalidModulePath)?;
        let mut slot = PROVIDERS.lock().map_err(|_| Error::ProviderState)?;
        if let Some((path, loaded)) = slot.as_ref() {
            if path != &module {
                return Err(Error::DifferentProvider);
            }
            return Ok(Self {
                _loaded: loaded.clone(),
            });
        }
        let default = Provider::load(None, "default")?;
        let gost = Provider::load(None, name)?;
        // The pinned provider registers this OID in its linked libcrypto. If
        // Rust linked another libcrypto major, digests can still appear usable,
        // while private PBE registration lands in the wrong global table.
        if openssl::asn1::Asn1Object::from_str("1.2.840.113549.1.12.1.80")?.nid()
            == openssl::nid::Nid::UNDEF
        {
            return Err(Error::IncompatibleProvider);
        }
        Md::fetch(None, "md_gost12_256", None)?;
        let loaded = std::sync::Arc::new(LoadedProviders {
            _gost: gost,
            _default: default,
        });
        *slot = Some((module, loaded.clone()));
        Ok(Self { _loaded: loaded })
    }

    /// Sign exact bytes using a matching software PKCS#8 key and public certificate.
    /// Returns 64 bytes s_BE || r_BE. Hashing and randomness are handled by OpenSSL.
    /// The caller owns and must appropriately protect/erase the input key buffer.
    /// Does not validate certificate trust, validity dates, revocation or key usage.
    pub fn sign(
        &self,
        data: &[u8],
        certificate_der: &[u8],
        pkcs8_der: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.import_pkcs8(certificate_der, pkcs8_der)?.sign(data)
    }

    /// Explicitly enable legacy algorithms for older PFX envelopes (for example RC2).
    /// Changes only the process's OpenSSL default context; not required for modern PKCS8.
    pub fn with_legacy(self) -> Result<Self, Error> {
        let mut legacy = LEGACY.lock().map_err(|_| Error::ProviderState)?;
        if legacy.is_none() {
            *legacy = Some(Provider::load(None, "legacy")?);
        }
        Ok(self)
    }

    /// Load a plain software key without exporting it back out of OpenSSL.
    pub fn import_pkcs8(
        &self,
        certificate_der: &[u8],
        pkcs8_der: &[u8],
    ) -> Result<SigningIdentity<'_>, Error> {
        check_der(pkcs8_der)?;
        self.bind(certificate_der, PKey::private_key_from_pkcs8(pkcs8_der)?)
    }

    /// Decrypt PKCS8 in memory using OpenSSL. Password octets may include NUL.
    /// The caller retains ownership of the password/input buffers.
    pub fn import_encrypted_pkcs8(
        &self,
        certificate_der: &[u8],
        encrypted_der: &[u8],
        password: &[u8],
    ) -> Result<SigningIdentity<'_>, Error> {
        check_der(encrypted_der)?;
        // The convenience passphrase API uses CString and panics on embedded NUL.
        // A length-aware callback preserves exact password bytes without truncation.
        let mut too_long = false;
        let key = PKey::private_key_from_pkcs8_callback(encrypted_der, |buffer| {
            if password.len() > buffer.len() {
                too_long = true;
                return Err(ErrorStack::get());
            }
            buffer[..password.len()].copy_from_slice(password);
            Ok(password.len())
        });
        if too_long {
            return Err(Error::PasswordTooLong);
        }
        self.bind(certificate_der, key?)
    }

    /// Load a PKCS12/PFX identity through OpenSSL, checking key/certificate equality.
    /// Password is UTF-8 without NUL, as required by the binding's PKCS12 API.
    /// Additional chain certificates do not establish trust and are not retained.
    /// Supported encryption schemes depend on the loaded providers/OpenSSL build.
    pub fn import_pkcs12(
        &self,
        pfx_der: &[u8],
        password: &str,
    ) -> Result<SigningIdentity<'_>, Error> {
        if password.contains('\0') {
            return Err(Error::InvalidPassword);
        }
        check_der(pfx_der)?;
        let parsed = Pkcs12::from_der(pfx_der)?.parse2(password)?;
        let private = parsed.pkey.ok_or(Error::MissingIdentity)?;
        let certificate = parsed.cert.ok_or(Error::MissingIdentity)?.to_der()?;
        self.bind(&certificate, private)
    }

    fn bind(
        &self,
        certificate_der: &[u8],
        private: PKey<Private>,
    ) -> Result<SigningIdentity<'_>, Error> {
        gost_sign_core::verification::decode_gost2012_256_public_key(certificate_der)
            .map_err(|_| Error::UnsupportedCertificate)?;
        let public = X509::from_der(certificate_der)?.public_key()?;
        if !private.public_eq(&public) {
            return Err(Error::KeyMismatch);
        }
        Ok(SigningIdentity {
            _provider: self,
            private,
            certificate: certificate_der.to_vec(),
        })
    }

    /// Verify raw GOST signature bytes using the ready-made native provider.
    /// Mathematical validity only; no certificate trust checks.
    pub fn verify(
        &self,
        data: &[u8],
        certificate_der: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        gost_sign_core::verification::decode_gost2012_256_public_key(certificate_der)
            .map_err(|_| Error::UnsupportedCertificate)?;
        if signature.len() != 64 {
            return Ok(false);
        }
        let public = X509::from_der(certificate_der)?.public_key()?;
        let digest = Md::fetch(None, "md_gost12_256", None)?;
        let mut ctx = MdCtx::new()?;
        ctx.digest_verify_init(Some(&digest), &public)?;
        ctx.digest_verify_update(data)?;
        Ok(ctx.digest_verify_final(signature)?)
    }
}

fn check_der(input: &[u8]) -> Result<(), Error> {
    use der::Decode;
    der::AnyRef::from_der(input).map_err(|_| Error::InvalidDer)?;
    Ok(())
}

/// An in-memory signing identity, bound to the lifetime of its provider.
/// No Debug/Clone or plaintext private-key export API is provided. OpenSSL owns the decoded
/// private key; caller-owned input/password buffers are not erased by this type.
/// Import checks key matching, not certificate trust, dates, revocation or usage.
pub struct SigningIdentity<'provider> {
    _provider: &'provider GostProvider,
    private: PKey<Private>,
    certificate: Vec<u8>,
}
impl SigningIdentity<'_> {
    /// Export standard PKCS#12 with PBES2/AES-256-CBC and SHA-256 MAC.
    /// Requires a new nonempty UTF-8 password (no NUL). No original PIN is stored.
    /// The imported software key must already have been decrypted successfully.
    /// Returns encrypted bytes only; does not write files.
    pub fn export_pkcs12(&self, password: &str) -> Result<Vec<u8>, Error> {
        if password.is_empty() {
            return Err(Error::EmptyExportPassword);
        }
        if password.contains('\0') {
            return Err(Error::InvalidPassword);
        }
        let pkcs8 = zeroize::Zeroizing::new(self.private.private_key_to_pkcs8()?);
        let pfx = gost_sign_pfx::export(&pkcs8, &self.certificate, password)
            .map_err(|e| Error::Pfx(e.to_string()))?;
        // Verify serialization preserves the full key/certificate binding.
        let parsed = Pkcs12::from_der(&pfx)?.parse2(password)?;
        if !parsed
            .pkey
            .ok_or(Error::MissingIdentity)?
            .public_eq(&self.private)
            || parsed.cert.ok_or(Error::MissingIdentity)?.to_der()? != self.certificate
        {
            return Err(Error::KeyMismatch);
        }
        Ok(pfx)
    }

    /// Public DER certificate only.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// Sign exact bytes with Streebog256; returns s_BE || r_BE after independent verification.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = Md::fetch(None, "md_gost12_256", None)?;
        let mut ctx = MdCtx::new()?;
        ctx.digest_sign_init(Some(&digest), &self.private)?;
        ctx.digest_sign_update(data)?;
        let mut signature = Vec::new();
        ctx.digest_sign_final_to_vec(&mut signature)?;
        if gost_sign_core::verification::verify_data_signature_gost2012_256(
            data,
            &self.certificate,
            &signature,
        ) != Ok(true)
        {
            return Err(Error::InvalidSignature);
        }
        Ok(signature)
    }

    /// Build detached CAdES-BES for exact bytes with this identity's certificate.
    pub fn sign_cades(&self, content: &[u8]) -> Result<Vec<u8>, Error> {
        let prepared = gost_sign_cms::PreparedDetachedSignature::new(content, &self.certificate)
            .map_err(|_| Error::UnsupportedCertificate)?;
        let signature = self.sign(prepared.signed_attributes_der())?;
        prepared
            .finish(&signature)
            .map_err(|_| Error::InvalidSignature)
    }
}
