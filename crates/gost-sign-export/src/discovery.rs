//! Read-only discovery: only public headers are opened, never private-key files.
use crate::container::{Container, Result};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug)]
pub enum Source {
    Directory(PathBuf),
    #[cfg(windows)]
    Registry {
        path: String,
        view: u32,
    },
}
impl Source {
    pub fn label(&self) -> String {
        match self {
            Self::Directory(path) => path.display().to_string(),
            #[cfg(windows)]
            Self::Registry { path, .. } => format!("Реестр HKLM\\{path}"),
        }
    }
    pub fn load(&self) -> Result<Container> {
        match self {
            Self::Directory(path) => Container::from_directory(path),
            #[cfg(windows)]
            Self::Registry { path, view } => registry_load(path, *view),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub source: Source,
    pub certificates: Vec<Vec<u8>>,
    pub notice: Option<String>,
}
#[derive(Default, Debug)]
pub struct Report {
    pub entries: Vec<Entry>,
    pub notices: Vec<String>,
}
/// Enumerate supported locations. No subprocess, PIN, private-file read or writes.
pub fn system() -> Report {
    #[cfg(unix)]
    let roots = vec![PathBuf::from("/var/opt/cprocsp/keys")];
    #[cfg(not(unix))]
    let mut roots = Vec::new();
    #[cfg(windows)]
    for var in ["LOCALAPPDATA", "APPDATA", "PROGRAMDATA"] {
        if let Some(base) = std::env::var_os(var) {
            for name in ["Crypto Pro", "CryptoPro"] {
                roots.push(PathBuf::from(&base).join(name));
            }
        }
    }
    let mut report = directories(&roots);
    #[cfg(windows)]
    registry_scan(&mut report);
    #[cfg(not(windows))]
    let _ = &mut report;
    report
}
/// Bounded recursive scan. Missing roots are normal; inaccessible roots are reported.
/// Symlinks are not followed, and private records are not opened.
pub fn directories(roots: &[PathBuf]) -> Report {
    let mut report = Report::default();
    let mut seen = BTreeSet::new();
    let mut remaining = 4096;
    for root in roots {
        walk(root, 0, &mut remaining, &mut seen, &mut report);
    }
    report.entries.sort_by_key(|e| e.source.label());
    report
}
fn walk(
    path: &Path,
    depth: usize,
    remaining: &mut usize,
    seen: &mut BTreeSet<PathBuf>,
    report: &mut Report,
) {
    if *remaining == 0 {
        return;
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            report
                .notices
                .push(format!("{}: {}", path.display(), crate::console_error(&e)));
            return;
        }
    };
    if !metadata.is_dir() {
        return;
    }
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canonical) {
        return;
    }
    *remaining -= 1;
    let header = path.join("header.key");
    if fs::symlink_metadata(&header).is_ok() || path.extension().is_some_and(|x| x == "000") {
        let (certificates, notice) = match read_header_file(&header)
            .and_then(|b| Ok(crate::certificates_from_header(&b)?))
        {
            Ok(certs) => (certs, None),
            Err(e) => (Vec::new(), Some(crate::console_error(e.as_ref()))),
        };
        report.entries.push(Entry {
            source: Source::Directory(path.to_path_buf()),
            certificates,
            notice,
        });
        return;
    }
    if depth == 3 {
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(v) => v,
        Err(e) => {
            report
                .notices
                .push(format!("{}: {}", path.display(), crate::console_error(&e)));
            return;
        }
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for child in paths {
        walk(&child, depth + 1, remaining, seen, report);
    }
    if *remaining == 0 {
        report
            .notices
            .push("Достигнут лимит поиска (4096 каталогов). Можно указать папку вручную".into());
    }
}
fn read_header_file(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("Заголовок должен быть обычным файлом, не ссылкой".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err("Заголовок превышает 16 КиБ".into());
    }
    Ok(bytes)
}
#[cfg(windows)]
fn registry_scan(report: &mut Report) {
    use winreg::{RegKey, enums::*};
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        for base in [
            r"SOFTWARE\Crypto Pro\Settings",
            r"SOFTWARE\CryptoPro\Settings",
        ] {
            let users = format!(r"{base}\Users");
            let mut key_roots = vec![format!(r"{base}\Keys")];
            if let Ok(users_key) = hklm.open_subkey_with_flags(&users, KEY_READ | view) {
                for sid in users_key
                    .enum_keys()
                    .filter_map(std::result::Result::ok)
                    .take(256)
                {
                    key_roots.push(format!(r"{users}\{sid}\Keys"));
                }
            }
            for root in key_roots {
                let keys = match hklm.open_subkey_with_flags(&root, KEY_READ | view) {
                    Ok(k) => k,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        report
                            .notices
                            .push(format!("Реестр {root}: {}", crate::console_error(&e)));
                        continue;
                    }
                };
                for name in keys
                    .enum_keys()
                    .filter_map(std::result::Result::ok)
                    .take(4096)
                {
                    let path = format!(r"{root}\{name}");
                    let certs = (|| -> Result<Vec<Vec<u8>>> {
                        let key = hklm.open_subkey_with_flags(&path, KEY_READ | view)?;
                        let value = key.get_raw_value("header.key")?;
                        if value.vtype != REG_BINARY || value.bytes.len() > 16384 {
                            return Err("Неподдерживаемый заголовок реестра".into());
                        }
                        Ok(crate::certificates_from_header(&value.bytes)?)
                    })();
                    let (certificates, notice) = match certs {
                        Ok(c) => (c, None),
                        Err(e) => (vec![], Some(crate::console_error(e.as_ref()))),
                    };
                    report.entries.push(Entry {
                        source: Source::Registry { path, view },
                        certificates,
                        notice,
                    });
                }
            }
        }
    }
}
#[cfg(windows)]
fn registry_load(path: &str, view: u32) -> Result<Container> {
    use winreg::{RegKey, enums::*};
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ | view)?;
    let mut records = Vec::new();
    for name in crate::container::FILES {
        let value = key.get_raw_value(name)?;
        if value.vtype != REG_BINARY || value.bytes.len() > 16384 {
            return Err("Неподдерживаемый формат записи контейнера в реестре".into());
        }
        records.push(zeroize::Zeroizing::new(value.bytes.into_owned()));
    }
    Container::from_storage_records(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Encode, Tag, TagNumber, asn1::AnyRef};
    fn header() -> Vec<u8> {
        let cert = include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
        let field = AnyRef::new(
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(5),
            },
            cert,
        )
        .expect("field")
        .to_der()
        .expect("DER");
        let mut body = AnyRef::new(Tag::Sequence, &field)
            .expect("seq")
            .to_der()
            .expect("DER");
        body.extend([4, 4, 0, 0, 0, 0]);
        AnyRef::new(Tag::Sequence, &body)
            .expect("header")
            .to_der()
            .expect("DER")
    }
    #[test]
    fn discovers_multiple_public_headers_without_private_files_or_symlinks() {
        let root = tempfile::tempdir().expect("root");
        for name in ["user/first.000", "user/second.001"] {
            let folder = root.path().join(name);
            fs::create_dir_all(&folder).expect("folder");
            fs::write(folder.join("header.key"), header()).expect("header");
        }
        let broken = root.path().join("user/broken.000");
        fs::create_dir(&broken).expect("broken");
        fs::write(broken.join("header.key"), b"broken").expect("broken header");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join("user"), root.path().join("alias"))
            .expect("symlink");
        let report = directories(&[
            root.path().to_path_buf(),
            root.path().join("missing"),
            root.path().to_path_buf(),
        ]);
        assert_eq!(report.entries.len(), 3);
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|e| !e.certificates.is_empty())
                .count(),
            2
        );
        assert!(report.entries.iter().any(|e| e.notice.is_some()));
        assert!(report.entries.iter().all(|e| e.source.load().is_err())); // Private records were never required by discovery.
    }
}
