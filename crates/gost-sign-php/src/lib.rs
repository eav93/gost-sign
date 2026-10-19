#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::{binary::Binary, binary_slice::BinarySlice, prelude::*};

/// Return a lowercase hexadecimal GOST R 34.11-2012 256-bit digest.
#[php_function]
#[php(name = "gost_sign_hash256")]
pub fn gost_sign_hash256(data: BinarySlice<'_, u8>) -> String {
    hex::encode(gost_sign_core::hash256(&data))
}

/// Return a lowercase hexadecimal GOST R 34.11-2012 512-bit digest.
#[php_function]
#[php(name = "gost_sign_hash512")]
pub fn gost_sign_hash512(data: BinarySlice<'_, u8>) -> String {
    hex::encode(gost_sign_core::hash512(&data))
}

/// Verify the mathematical signature only; does not establish certificate trust.
#[php_function]
#[php(name = "gost_sign_verify_certificate_tc26_256_a")]
pub fn gost_sign_verify_certificate_tc26_256_a(
    certificate_der: BinarySlice<'_, u8>,
    issuer_der: BinarySlice<'_, u8>,
) -> PhpResult<bool> {
    gost_sign_core::verification::verify_certificate_signature_tc26_256_a(
        &certificate_der,
        &issuer_der,
    )
    .map_err(|error| PhpException::from_message(error.to_string()))
}

/// Exact DER signed attributes for an external signer; this function does not sign.
#[php_function]
#[php(name = "gost_sign_cades_signed_attributes")]
pub fn gost_sign_cades_signed_attributes(
    content: BinarySlice<'_, u8>,
    certificate_der: BinarySlice<'_, u8>,
) -> PhpResult<Binary<u8>> {
    let prepared = gost_sign_cms::PreparedDetachedSignature::new(&content, &certificate_der)
        .map_err(|error| PhpException::from_message(error.to_string()))?;
    Ok(Binary::from(prepared.signed_attributes_der().to_vec()))
}

/// Assemble detached CMS from a raw external signature. Does not validate that signature.
#[php_function]
#[php(name = "gost_sign_cades_assemble")]
pub fn gost_sign_cades_assemble(
    content: BinarySlice<'_, u8>,
    certificate_der: BinarySlice<'_, u8>,
    signature: BinarySlice<'_, u8>,
) -> PhpResult<Binary<u8>> {
    let prepared = gost_sign_cms::PreparedDetachedSignature::new(&content, &certificate_der)
        .map_err(|error| PhpException::from_message(error.to_string()))?;
    prepared
        .finish(&signature)
        .map(Binary::from)
        .map_err(|error| PhpException::from_message(error.to_string()))
}

/// Verify detached CMS mathematically; certificate trust is not checked.
#[php_function]
#[php(name = "gost_sign_cades_verify")]
pub fn gost_sign_cades_verify(
    content: BinarySlice<'_, u8>,
    cms_der: BinarySlice<'_, u8>,
) -> PhpResult<bool> {
    gost_sign_cms::verification::verify_detached(&content, &cms_der)
        .map_err(|error| PhpException::from_message(error.to_string()))
}

/// Sign through a locally installed OpenSSL provider, using a software PKCS#8 key.
/// This does not import CryptoPro containers or establish certificate trust.
#[cfg(feature = "native-openssl")]
#[php_function]
#[php(name = "gost_sign_cades_sign_pkcs8")]
pub fn gost_sign_cades_sign_pkcs8(
    content: BinarySlice<'_, u8>,
    certificate_der: BinarySlice<'_, u8>,
    pkcs8_der: BinarySlice<'_, u8>,
    provider_module: &str,
) -> PhpResult<Binary<u8>> {
    let provider = gost_sign_openssl::GostProvider::load(std::path::Path::new(provider_module))
        .map_err(|error| PhpException::from_message(error.to_string()))?;
    let prepared = gost_sign_cms::PreparedDetachedSignature::new(&content, &certificate_der)
        .map_err(|error| PhpException::from_message(error.to_string()))?;
    let signature = provider
        .sign(
            prepared.signed_attributes_der(),
            &certificate_der,
            &pkcs8_der,
        )
        .map_err(|error| PhpException::from_message(error.to_string()))?;
    prepared
        .finish(&signature)
        .map(Binary::from)
        .map_err(|error| PhpException::from_message(error.to_string()))
}

/// Decrypt a software PKCS8 key in memory and sign detached CAdES.
#[cfg(feature = "native-openssl")]
#[php_function]
#[php(name = "gost_sign_cades_sign_encrypted_pkcs8")]
pub fn gost_sign_cades_sign_encrypted_pkcs8(
    content: BinarySlice<'_, u8>,
    certificate_der: BinarySlice<'_, u8>,
    encrypted_der: BinarySlice<'_, u8>,
    password: BinarySlice<'_, u8>,
    provider_module: &str,
) -> PhpResult<Binary<u8>> {
    let provider = gost_sign_openssl::GostProvider::load(std::path::Path::new(provider_module))
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    let identity = provider
        .import_encrypted_pkcs8(&certificate_der, &encrypted_der, &password)
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    identity
        .sign_cades(&content)
        .map(Binary::from)
        .map_err(|e| PhpException::from_message(e.to_string()))
}

/// Load a PFX identity and sign; legacy algorithms are an explicit opt-in.
#[cfg(feature = "native-openssl")]
#[php_function]
#[php(name = "gost_sign_cades_sign_pkcs12")]
pub fn gost_sign_cades_sign_pkcs12(
    content: BinarySlice<'_, u8>,
    pfx_der: BinarySlice<'_, u8>,
    password: &str,
    provider_module: &str,
    legacy: bool,
) -> PhpResult<Binary<u8>> {
    let provider = gost_sign_openssl::GostProvider::load(std::path::Path::new(provider_module))
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    let provider = if legacy {
        provider
            .with_legacy()
            .map_err(|e| PhpException::from_message(e.to_string()))?
    } else {
        provider
    };
    let identity = provider
        .import_pkcs12(&pfx_der, password)
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    identity
        .sign_cades(&content)
        .map(Binary::from)
        .map_err(|e| PhpException::from_message(e.to_string()))
}

/// Подпись стандартным PFX: полностью Rust, без внешнего провайдера.
#[php_function]
#[php(name = "gost_sign_cades_sign_pfx")]
pub fn gost_sign_cades_sign_pfx(
    content: BinarySlice<'_, u8>,
    pfx_der: BinarySlice<'_, u8>,
    password: &str,
) -> PhpResult<Binary<u8>> {
    let identity = gost_sign_rust::SigningIdentity::import_pkcs12(&pfx_der, password)
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    identity
        .sign_cades(&content)
        .map(Binary::from)
        .map_err(|e| PhpException::from_message(e.to_string()))
}

/// Открытый сертификат DER из PFX после проверки пароля и соответствия ключу.
#[php_function]
#[php(name = "gost_sign_pfx_certificate")]
pub fn gost_sign_pfx_certificate(
    pfx_der: BinarySlice<'_, u8>,
    password: &str,
) -> PhpResult<Binary<u8>> {
    let identity = gost_sign_rust::SigningIdentity::import_pkcs12(&pfx_der, password)
        .map_err(|e| PhpException::from_message(e.to_string()))?;
    Ok(Binary::from(identity.certificate_der().to_vec()))
}

#[php_module]

pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    let module = module
        .function(wrap_function!(gost_sign_cades_sign_pfx))
        .function(wrap_function!(gost_sign_pfx_certificate))
        .function(wrap_function!(gost_sign_hash256))
        .function(wrap_function!(gost_sign_hash512))
        .function(wrap_function!(gost_sign_verify_certificate_tc26_256_a))
        .function(wrap_function!(gost_sign_cades_signed_attributes))
        .function(wrap_function!(gost_sign_cades_assemble))
        .function(wrap_function!(gost_sign_cades_verify));
    #[cfg(feature = "native-openssl")]
    let module = module
        .function(wrap_function!(gost_sign_cades_sign_pkcs8))
        .function(wrap_function!(gost_sign_cades_sign_encrypted_pkcs8))
        .function(wrap_function!(gost_sign_cades_sign_pkcs12));
    module
}
