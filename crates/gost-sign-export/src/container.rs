//! Lossless six-file CryptoPro container transfer. Not private-scalar decoding.

use der::{Reader, Tag, Tagged, asn1::AnyRef};
use std::{error::Error, fs, io::Read, path::Path};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const FILES: [&str; 6] = [
    "masks.key",
    "primary.key",
    "header.key",
    "masks2.key",
    "primary2.key",
    "name.key",
];

const LIMIT: usize = 16384;

/// Sensitive records are zeroized on drop. No Debug or plaintext export accessor.
pub struct Container {
    pub(crate) records: Vec<Zeroizing<Vec<u8>>>,
}

impl Container {
    /// Accepts the previously observed Lite 256-bit layout; rejects other profiles.
    /// Token file allocation padding is excluded at the first DER record boundary.
    pub fn from_token_records(records: Vec<Zeroizing<Vec<u8>>>) -> Result<Self> {
        Self::validate(records, true)
    }

    pub fn from_directory(path: &Path) -> Result<Self> {
        let mut records = Vec::new();
        for name in FILES {
            let path = path.join(name);
            if !fs::symlink_metadata(&path)?.file_type().is_file() {
                return Err(format!("{name}: требуется обычный файл, не ссылка").into());
            }
            let mut record = Zeroizing::new(Vec::new());
            fs::File::open(path)?
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut record)?;
            records.push(record);
        }
        Self::validate(records, false)
    }

    #[cfg(windows)]
    pub(crate) fn from_storage_records(records: Vec<Zeroizing<Vec<u8>>>) -> Result<Self> {
        Self::validate(records, false)
    }

    fn validate(mut records: Vec<Zeroizing<Vec<u8>>>, padded: bool) -> Result<Self> {
        if records.len() != FILES.len() {
            return Err("Нужны все шесть файлов контейнера".into());
        }
        for (index, record) in records.iter_mut().enumerate() {
            if record.len() > LIMIT {
                return Err("Файл контейнера превышает лимит".into());
            }
            let mut reader = der::SliceReader::new(record)?;
            let value: AnyRef<'_> = reader.decode()?;
            value.tag().assert_eq(Tag::Sequence)?;
            let end: usize = reader.position().try_into()?;
            if !padded && !reader.is_finished() {
                return Err("Лишние байты после DER".into());
            }
            value.sequence(|reader| -> der::Result<()> {
                let mut fields = Vec::new();
                while !reader.is_finished() {
                    let field: AnyRef<'_> = reader.decode()?;
                    fields.push((field.tag(), field.value().len()));
                }
                let valid = match index {
                    0 | 3 => {
                        fields
                            == [
                                (Tag::OctetString, 32),
                                (Tag::OctetString, 12),
                                (Tag::OctetString, 4),
                            ]
                    }
                    1 | 4 => fields == [(Tag::OctetString, 32)],
                    2 => {
                        fields.len() == 2
                            && fields[0].0 == Tag::Sequence
                            && fields[1] == (Tag::OctetString, 4)
                    }
                    5 => fields.len() == 1 && fields[0].0 == Tag::Ia5String && fields[0].1 > 0,
                    _ => false,
                };
                if !valid {
                    return Err(Tag::Sequence.value_error().into());
                }
                Ok(())
            })?;
            // Wipe allocation padding before truncation.
            use zeroize::Zeroize;
            record[end..].zeroize();
            record.truncate(end);
        }
        crate::certificates_from_header(&records[2])?;
        Ok(Self { records })
    }

    pub fn certificates(&self) -> Result<Vec<Vec<u8>>> {
        Ok(crate::certificates_from_header(&self.records[2])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    fn record(fields: &[(Tag, &[u8])]) -> Vec<u8> {
        let mut content = Vec::new();
        for (tag, value) in fields {
            content.extend(
                AnyRef::new(*tag, value)
                    .expect("field")
                    .to_der()
                    .expect("DER"),
            );
        }
        AnyRef::new(Tag::Sequence, &content)
            .expect("sequence")
            .to_der()
            .expect("DER")
    }
    fn fixture() -> Vec<Zeroizing<Vec<u8>>> {
        let masks = record(&[
            (Tag::OctetString, &[1; 32]),
            (Tag::OctetString, &[2; 12]),
            (Tag::OctetString, &[3; 4]),
        ]);
        let primary = record(&[(Tag::OctetString, &[4; 32])]);
        let header = record(&[(Tag::Sequence, &[]), (Tag::OctetString, &[5; 4])]);
        let name = record(&[(Tag::Ia5String, b"public-test")]);
        vec![masks.clone(), primary.clone(), header, masks, primary, name]
            .into_iter()
            .map(Zeroizing::new)
            .collect()
    }
    #[test]
    fn padding_is_only_accepted_for_token_files() {
        let original = fixture();
        let padded = || {
            original
                .iter()
                .map(|r| {
                    let mut r = r.to_vec();
                    r.extend([0xff; 12]);
                    Zeroizing::new(r)
                })
                .collect()
        };
        assert!(Container::validate(padded(), false).is_err());
        let result = Container::from_token_records(padded()).expect("valid");
        for (a, b) in original.iter().zip(result.records.iter()) {
            assert_eq!(**a, **b);
        }
    }
    #[test]
    fn missing_and_wrong_records_are_rejected() {
        let mut missing = fixture();
        missing.pop();
        assert!(Container::validate(missing, false).is_err());
        let mut wrong = fixture();
        wrong.swap(0, 1);
        assert!(Container::validate(wrong, false).is_err());
    }
    #[test]
    #[ignore = "requires disposable CSP fixture"]
    fn reads_actual_csp_directory() {
        let path =
            std::path::PathBuf::from(std::env::var_os("GOST_CSP_FIXTURE_DIR").expect("fixture"));
        let container =
            Container::from_directory(&path.join("hdimage-test/gost-sig.000")).expect("read");
        assert_eq!(
            container.certificates().expect("cert"),
            [fs::read(path.join("test-csp.cer")).expect("public certificate")]
        );
    }
}
