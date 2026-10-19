//! Experimental Rutoken Lite 1010 profile. No data writes; optional one-shot PIN VERIFY.
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged, asn1::AnyRef};
use std::{
    error::Error,
    ffi::{CStr, CString},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ATR: &[u8] = b"\x3b\x8b\x01Rutokenlite\xc2";

#[derive(Debug)]
struct CardStatus(u16);
impl std::fmt::Display for CardStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 & 0xfff0 == 0x63c0 {
            return write!(
                f,
                "Неверный PIN; осталось попыток: {}. Повторная попытка не выполнялась",
                self.0 & 15
            );
        }
        if self.0 == 0x6983 {
            return f.write_str("PIN заблокирован; операция остановлена");
        }
        write!(f, "Карта вернула {:04X}; операция остановлена", self.0)
    }
}
impl Error for CardStatus {}

pub fn readers() -> Result<Vec<CString>> {
    Ok(pcsc::Context::establish(pcsc::Scope::User)?.list_readers_owned()?)
}

/// Read the six files of the observed Lite profile in one transaction.
/// No PIN guessing, flag edits, or writes. Protected files fail immediately.
pub fn container(reader: &CStr, directory: u16) -> Result<crate::container::Container> {
    container_with_pin(reader, directory, || Err("Требуется PIN токена".into()))
}

/// Ask once for a user PIN only after access denial; never guess or retry a PIN.
/// Experimental Lite profile: global user reference 2, ISO VERIFY.
pub fn container_with_pin(
    reader: &CStr,
    directory: u16,
    request_pin: impl FnMut() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<crate::container::Container> {
    if !(0x0a00..=0x0aff).contains(&directory) {
        return Err("Каталог контейнера должен быть в диапазоне 0a00–0aff".into());
    }
    let context = pcsc::Context::establish(pcsc::Scope::User)?;
    let mut card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
    let transaction = card.transaction()?;
    if transaction.status2_owned()?.atr() != ATR {
        return Err("Неподдерживаемый ATR".into());
    }
    let records = read_container(
        directory,
        |command| {
            let mut response = zeroize::Zeroizing::new([0u8; 4096]);
            Ok(transaction.transmit(command, &mut *response)?.to_vec())
        },
        request_pin,
    )?;
    crate::container::Container::from_token_records(records)
}

fn read_container(
    directory: u16,
    mut send: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    mut pin: impl FnMut() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
    let mut authenticated = false;
    let result = (|| {
        let mut records = Vec::new();
        for file in 0x0a01..=0x0a06 {
            let first = read_file(directory, file, &mut send);
            let record = match first {
                Err(error)
                    if !authenticated
                        && error
                            .downcast_ref::<CardStatus>()
                            .is_some_and(|s| s.0 == 0x6982) =>
                {
                    let pin = pin()?;
                    if pin.is_empty() || pin.len() > 16 {
                        return Err("PIN должен содержать от 1 до 16 байт".into());
                    }
                    let mut verify = zeroize::Zeroizing::new(vec![0, 0x20, 0, 2, pin.len() as u8]);
                    verify.extend_from_slice(&pin);
                    exchange(&mut send, &verify)?;
                    authenticated = true;
                    read_file(directory, file, &mut send)?
                }
                result => result?,
            };
            records.push(zeroize::Zeroizing::new(record));
        }
        Ok(records)
    })();
    if authenticated {
        // Reset access rights we enabled, not the token contents.
        exchange(&mut send, &[0x80, 0x40, 0, 0])?;
    }
    result
}

/// Read only header file 0a03 in the selected CryptoPro container directory.
/// The supported ATR/profile comes from the locally inventoried Lite 1010.
/// A protected header fails without attempting PIN authentication.
pub fn certificates(reader: &CStr, container: u16) -> Result<Vec<Vec<u8>>> {
    if !(0x0a00..=0x0aff).contains(&container) {
        return Err("Каталог контейнера должен быть в диапазоне 0a00–0aff".into());
    }
    let context = pcsc::Context::establish(pcsc::Scope::User)?;
    let mut card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
    let transaction = card.transaction()?;
    if transaction.status2_owned()?.atr() != ATR {
        return Err("ATR не соответствует поддерживаемому профилю Рутокен Lite 1010".into());
    }
    let header = read_header(container, |command| {
        let mut response = [0u8; 4096];
        Ok(transaction.transmit(command, &mut response)?.to_vec())
    })?;
    crate::certificates_from_header(&header).map_err(Into::into)
}

/// Metadata discovered without authentication or private-record reads.
#[derive(Clone, Debug)]
pub struct DiscoveredContainer {
    pub directory: u16,
    pub certificates: Vec<Vec<u8>>,
    pub notice: Option<String>,
}

pub fn discover(reader: &CStr, progress: impl FnMut(u16)) -> Result<Vec<DiscoveredContainer>> {
    let context = pcsc::Context::establish(pcsc::Scope::User)?;
    let mut card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
    let transaction = card.transaction()?;
    if transaction.status2_owned()?.atr() != ATR {
        return Err("Считыватель не содержит поддерживаемый Рутокен Lite 1010".into());
    }
    scan_headers(
        |command| {
            let mut response = [0u8; 4096];
            Ok(transaction.transmit(command, &mut response)?.to_vec())
        },
        progress,
    )
}

fn scan_headers(
    mut send: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    mut progress: impl FnMut(u16),
) -> Result<Vec<DiscoveredContainer>> {
    let mut result = Vec::new();
    for fid in [0x3f00u16, 0x1000, 0x1003] {
        let [hi, lo] = fid.to_be_bytes();
        exchange(&mut send, &[0, 0xa4, 0, 0, 2, hi, lo, 0])?;
    }
    for directory in 0x0a00..=0x0aff {
        progress(directory);
        match read_header(directory, &mut send) {
            Ok(header) => {
                let (certificates, notice) = match crate::certificates_from_header(&header) {
                    Ok(c) => (c, None),
                    Err(_) => (
                        vec![],
                        Some("Не удалось разобрать открытый сертификат".into()),
                    ),
                };
                result.push(DiscoveredContainer {
                    directory,
                    certificates,
                    notice,
                });
            }
            Err(e)
                if e.downcast_ref::<CardStatus>()
                    .is_some_and(|s| s.0 == 0x6a82) => {}
            Err(e)
                if e.downcast_ref::<CardStatus>()
                    .is_some_and(|s| s.0 == 0x6982) =>
            {
                result.push(DiscoveredContainer { directory, certificates: vec![], notice: Some("Для чтения сертификата требуется авторизация; PIN при поиске не запрашивается".into()) });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

fn exchange(send: &mut impl FnMut(&[u8]) -> Result<Vec<u8>>, command: &[u8]) -> Result<Vec<u8>> {
    let mut response = send(command)?;
    let mut data = Vec::new();
    for _ in 0..16 {
        if response.len() < 2 {
            return Err("Ответ карты без статуса".into());
        }
        let status = &response[response.len() - 2..];
        let sw = u16::from_be_bytes([status[0], status[1]]);
        data.extend_from_slice(&response[..response.len() - 2]);
        if data.len() > 16384 {
            return Err("Слишком большой ответ карты".into());
        }
        if sw == 0x9000 {
            return Ok(data);
        }
        if sw >> 8 != 0x61 {
            return Err(CardStatus(sw).into());
        }
        response = send(&[0, 0xc0, 0, 0, sw as u8])?;
    }
    Err("Превышен лимит GET RESPONSE".into())
}

fn file_size(fci: &[u8], expected_fid: u16) -> Result<usize> {
    let envelope = AnyRef::from_der(fci)?;
    if ![
        TagNumber(15).application(true),
        TagNumber(2).application(true),
    ]
    .contains(&envelope.tag())
    {
        return Err("Ожидался FCI/FCP".into());
    }
    let mut reader = SliceReader::new(envelope.value())?;
    let (mut fid, mut descriptor, mut size) = (None, None, None);
    while !reader.is_finished() {
        let field: AnyRef<'_> = reader.decode()?;
        let slot = match field.tag() {
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(3),
            } => &mut fid,
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(2),
            } => &mut descriptor,
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(0),
            } => &mut size,
            _ => continue,
        };
        if slot.replace(field.value()).is_some() {
            return Err("Повторное поле FCI".into());
        }
    }
    if fid != Some(&expected_fid.to_be_bytes()[..]) || descriptor != Some(&[1, 0][..]) {
        return Err("Выбран неожиданный файл контейнера".into());
    }
    let size = size.ok_or("Нет размера файла")?;
    if size.is_empty() || size.len() > 2 {
        return Err("Некорректный размер файла".into());
    }
    let size = size
        .iter()
        .fold(0usize, |n, byte| n * 256 + usize::from(*byte));
    if !(1..=16384).contains(&size) {
        return Err("Размер заголовка вне лимита".into());
    }
    Ok(size)
}

fn read_header(container: u16, send: impl FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    read_file(container, 0x0a03, send)
}

fn read_file(
    container: u16,
    file: u16,
    mut send: impl FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut fci = Vec::new();
    for fid in [0x3f00u16, 0x1000, 0x1003, container, file] {
        let [hi, lo] = fid.to_be_bytes();
        fci = exchange(&mut send, &[0, 0xa4, 0, 0, 2, hi, lo, 0])?;
    }
    let size = file_size(&fci, file)?;
    let mut result = Vec::with_capacity(size);
    while result.len() < size {
        let offset = result.len();
        let length = (size - offset).min(240);
        let chunk = exchange(
            &mut send,
            &[0, 0xb0, (offset >> 8) as u8, offset as u8, length as u8],
        )?;
        if chunk.len() != length {
            return Err("Неполное чтение заголовка".into());
        }
        result.extend(chunk);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fci(size: u16) -> Vec<u8> {
        let [hi, lo] = size.to_be_bytes();
        vec![0x6f, 12, 0x83, 2, 0x0a, 3, 0x82, 2, 1, 0, 0x80, 2, hi, lo]
    }
    #[test]
    fn token_login_is_once_and_access_is_reset() {
        let mut logged_in = false;
        let mut verify_count = 0;
        let mut prompt_count = 0;
        let mut logout_count = 0;
        let records = read_container(
            0x0a00,
            |command| match command[1] {
                0x20 => {
                    verify_count += 1;
                    assert_eq!(command, [0, 0x20, 0, 2, 4, 49, 50, 51, 52]);
                    logged_in = true;
                    Ok(vec![0x90, 0])
                }
                0x40 => {
                    logout_count += 1;
                    logged_in = false;
                    Ok(vec![0x90, 0])
                }
                0xa4 => {
                    let mut meta = fci(1);
                    meta[4] = command[5];
                    meta[5] = command[6];
                    meta.extend([0x90, 0]);
                    Ok(meta)
                }
                0xb0 if !logged_in => Ok(vec![0x69, 0x82]),
                0xb0 => Ok(vec![7, 0x90, 0]),
                _ => panic!("unexpected command"),
            },
            || {
                prompt_count += 1;
                Ok(zeroize::Zeroizing::new(b"1234".to_vec()))
            },
        )
        .expect("read");
        assert_eq!(records.len(), 6);
        assert_eq!((verify_count, prompt_count, logout_count), (1, 1, 1));
        assert!(!logged_in);
    }
    #[test]
    fn wrong_pin_is_not_retried() {
        let mut count = 0;
        let result = read_container(
            0x0a00,
            |command| {
                if command[1] == 0x20 {
                    count += 1;
                    Ok(vec![0x63, 0xc9])
                } else {
                    Ok(vec![0x69, 0x82])
                }
            },
            || Ok(zeroize::Zeroizing::new(b"1234".to_vec())),
        );
        assert!(result.is_err());
        assert_eq!(count, 1);
    }
    #[test]
    fn exact_path_chunking_and_read_only_commands() {
        let mut paths = Vec::new();
        let mut offsets = Vec::new();
        let bytes = read_header(0x0a00, |cmd| {
            let mut response = match cmd[1] {
                0xa4 => {
                    paths.push([cmd[5], cmd[6]]);
                    fci(251)
                }
                0xb0 => {
                    offsets.push((cmd[2], cmd[3], cmd[4]));
                    vec![7; cmd[4] as usize]
                }
                _ => panic!("unexpected command"),
            };
            response.extend([0x90, 0]);
            Ok(response)
        })
        .expect("read");
        assert_eq!(bytes, vec![7; 251]);
        assert_eq!(
            paths,
            [[0x3f, 0], [0x10, 0], [0x10, 3], [0x0a, 0], [0x0a, 3]]
        );
        assert_eq!(offsets, [(0, 0, 240), (0, 240, 11)]);
    }
    #[test]
    fn access_denied_stops_without_pin_retry() {
        let mut count = 0;
        assert!(
            read_header(0x0a00, |_| {
                count += 1;
                Ok(vec![0x69, 0x82])
            })
            .is_err()
        );
        assert_eq!(count, 1);
    }
    #[test]
    fn continuation_and_malformed_responses() {
        let mut calls = 0;
        assert_eq!(
            exchange(
                &mut |cmd| {
                    calls += 1;
                    if calls == 1 {
                        Ok(vec![1, 0x61, 2])
                    } else {
                        assert_eq!(cmd, [0, 0xc0, 0, 0, 2]);
                        Ok(vec![2, 3, 0x90, 0])
                    }
                },
                &[0, 0xa4]
            )
            .expect("response"),
            [1, 2, 3]
        );
        assert!(exchange(&mut |_| Ok(vec![0]), &[0]).is_err());
        assert!(file_size(&fci(0), 0x0a03).is_err());
        assert!(file_size(&fci(16385), 0x0a03).is_err());
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn sparse_and_protected_containers_are_detected_without_pin_or_private_reads() {
        let mut selected = 0;
        let mut scans = 0;
        let found = scan_headers(
            |cmd| {
                assert_ne!(cmd.get(1), Some(&0x20)); // No VERIFY, even for a protected header.
                assert_eq!(cmd.get(1), Some(&0xa4)); // This fixture denies headers before READ BINARY.
                let fid = u16::from_be_bytes([cmd[5], cmd[6]]);
                if fid == 0x3f00 {
                    selected = 0;
                }
                if (0x0a00..=0x0aff).contains(&fid) {
                    if fid == 0x0a03 && selected != 0 {
                        return Ok(vec![0x69, 0x82]);
                    }
                    selected = 0;
                    if fid == 0x0a01 || fid == 0x0aff {
                        selected = fid;
                        return Ok(vec![0x90, 0]);
                    }
                    return Ok(vec![0x6a, 0x82]);
                }
                Ok(vec![0x90, 0])
            },
            |_| scans += 1,
        )
        .expect("scan");
        assert_eq!(scans, 256);
        assert_eq!(
            found.iter().map(|e| e.directory).collect::<Vec<_>>(),
            [0x0a01, 0x0aff]
        );
        assert!(
            found
                .iter()
                .all(|e| e.certificates.is_empty() && e.notice.is_some())
        );
    }
}
