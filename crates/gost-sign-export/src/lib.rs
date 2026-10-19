//! Public certificate extraction only. Does not read or export private keys.
use der::{Decode, Reader, Tag, TagNumber, Tagged, asn1::AnyRef};

#[cfg(feature = "pcsc")]
pub mod token;

pub mod container;
pub mod cryptopro;
pub mod discovery;

/// Russian diagnostics for errors that would otherwise come from system libraries.
pub fn console_error(error: &(dyn std::error::Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        let message = match error.kind() {
            std::io::ErrorKind::NotFound => "Файл или каталог не найден",
            std::io::ErrorKind::AlreadyExists => "Файл уже существует; перезапись запрещена",
            std::io::ErrorKind::PermissionDenied => "Недостаточно прав доступа",
            std::io::ErrorKind::UnexpectedEof => "Данные или ввод неожиданно закончились",
            _ => "Ошибка чтения или записи",
        };
        return match error.raw_os_error() {
            Some(code) => format!("{message} (системный код {code})"),
            None => message.into(),
        };
    }
    if error.is::<der::Error>() {
        return "Некорректная структура ASN.1/DER".into();
    }
    if error.is::<std::num::ParseIntError>() {
        return "Введите корректное число".into();
    }
    if error.is::<std::array::TryFromSliceError>() {
        return "Некорректная длина поля данных".into();
    }
    #[cfg(feature = "pcsc")]
    if let Some(error) = error.downcast_ref::<pcsc::Error>() {
        return format!(
            "Ошибка службы смарт-карт PC/SC, код 0x{:08X}",
            *error as u32
        );
    }
    error.to_string()
}

/// Extract embedded primary/secondary certificates from a CryptoPro header.key.
///
/// Parses the outer DER envelope and direct context-specific fields 5/6 only.
/// Does not authenticate the container MAC, validate trust, or follow certificate
/// links. Other content fields are opaque: this is not a full container validator.
pub fn certificates_from_header(input: &[u8]) -> Result<Vec<Vec<u8>>, der::Error> {
    AnyRef::from_der(input)?.sequence(|outer| {
        let content: AnyRef<'_> = outer.decode()?;
        let mac: AnyRef<'_> = outer.decode()?;
        mac.tag().assert_eq(Tag::OctetString)?;
        content.sequence(|reader| {
            let mut certificates = Vec::new();
            let mut seen = [false; 2];
            while !reader.is_finished() {
                let field: AnyRef<'_> = reader.decode()?;
                for (index, number) in [TagNumber(5), TagNumber(6)].iter().enumerate() {
                    if field.tag()
                        == (Tag::ContextSpecific {
                            constructed: false,
                            number: *number,
                        })
                    {
                        if seen[index] {
                            return Err(der::Error::from(field.tag().value_error()));
                        }
                        seen[index] = true;
                        gost_sign_core::parse_certificate_der(field.value())?;
                        certificates.push(field.value().to_vec());
                    }
                }
            }
            Ok(certificates)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    const CERT: &[u8] =
        include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");

    fn wrap(tag: Tag, value: &[u8]) -> Vec<u8> {
        AnyRef::new(tag, value)
            .expect("test value")
            .to_der()
            .expect("test DER")
    }
    fn header(fields: &[u8]) -> Vec<u8> {
        let mut body = wrap(Tag::Sequence, fields);
        body.extend(wrap(Tag::OctetString, b"test MAC not authenticated"));
        wrap(Tag::Sequence, &body)
    }
    fn cert_field() -> Vec<u8> {
        wrap(
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(5),
            },
            CERT,
        )
    }
    #[test]
    fn extracts_exact_certificate_and_rejects_trailing_bytes() {
        let mut input = header(&cert_field());
        assert_eq!(
            certificates_from_header(&input).expect("certificate"),
            [CERT]
        );
        input.push(0);
        assert!(certificates_from_header(&input).is_err());
    }
    #[test]
    fn rejects_duplicate_and_invalid_certificate() {
        let mut fields = cert_field();
        fields.extend(cert_field());
        assert!(certificates_from_header(&header(&fields)).is_err());
        assert!(
            certificates_from_header(&header(&wrap(
                Tag::ContextSpecific {
                    constructed: false,
                    number: TagNumber(5)
                },
                b"invalid"
            )))
            .is_err()
        );
    }
    #[test]
    fn does_not_search_nested_fields_or_follow_links() {
        let nested = wrap(Tag::Sequence, &cert_field());
        assert!(
            certificates_from_header(&header(&nested))
                .expect("empty")
                .is_empty()
        );
    }
    #[test]
    #[ignore = "requires disposable CSP fixture in GOST_CSP_FIXTURE_DIR"]
    fn actual_csp_header() {
        let dir = std::path::PathBuf::from(
            std::env::var_os("GOST_CSP_FIXTURE_DIR").expect("fixture dir"),
        );
        let header =
            std::fs::read(dir.join("hdimage-test/gost-sig.000/header.key")).expect("header");
        let expected = std::fs::read(dir.join("test-csp.cer")).expect("cert");
        assert_eq!(
            certificates_from_header(&header).expect("extract"),
            [expected]
        );
    }
}
