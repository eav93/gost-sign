//! Общий интерактивный интерфейс экспорта и подписи.
use gost_sign_export::container::Container;
use gost_sign_rust::SigningIdentity;
use std::{
    error::Error,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Debug)]
struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Действие отменено")
    }
}
impl Error for Cancelled {}
fn prompt(text: &str) -> Result<String> {
    print!("{text}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Ввод завершён").into());
    }
    let line = line.trim().to_owned();
    if line == ":назад" {
        return Err(Box::new(Cancelled));
    }
    Ok(line)
}
fn path(text: &str, default: Option<&Path>) -> Result<PathBuf> {
    let label = match default {
        Some(p) => format!("{text} [{}]: ", p.display()),
        None => format!("{text}: "),
    };
    let value = prompt(&label)?;
    if value.is_empty() {
        return default
            .map(Path::to_path_buf)
            .ok_or_else(|| "Путь не указан".into());
    }
    let value = unquote(&value);
    Ok(PathBuf::from(value))
}
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
}
fn destination(text: &str, default: &Path) -> Result<PathBuf> {
    let output = path(text, Some(default))?;
    if output.try_exists()? {
        return Err("Файл уже существует. Выберите новое имя; перезапись отключена".into());
    }
    Ok(output)
}
fn secret(text: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(text)?))
}
fn read_small(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Файл ключа, сертификата или подписи превышает 4 МиБ".into());
    }
    Ok(bytes)
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    println!("Сохранено: {}", path.display());
    Ok(())
}
fn show_certificate(bytes: &[u8]) -> Result<()> {
    let cert = gost_sign_core::parse_certificate_der(bytes)?;
    let tbs = cert.tbs_certificate();
    let field = |oid: &str| -> Option<String> {
        tbs.subject()
            .iter()
            .find(|a| a.oid.to_string() == oid)
            .map(|a| {
                String::from_utf8_lossy(a.value.value())
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect()
            })
    };
    println!(
        "Владелец: {}",
        field("2.5.4.3").unwrap_or_else(|| tbs.subject().to_string())
    );
    if let Some(ogrnip) = field("1.2.643.100.5") {
        println!("ИП, ОГРНИП: {ogrnip}");
    }
    if let Some(org) = field("2.5.4.10") {
        println!("Организация: {org}");
    }
    if let Some(ogrn) = field("1.2.643.100.1") {
        println!("ОГРН: {ogrn}");
    }
    if let Some(inn) = field("1.2.643.3.131.1.1") {
        println!("ИНН: {inn}");
    }
    println!(
        "Срок: {} — {}\nИздатель: {}",
        tbs.validity().not_before,
        tbs.validity().not_after,
        tbs.issuer()
    );
    Ok(())
}
fn open_pfx() -> Result<SigningIdentity> {
    let file = path("Файл с ключом (.pfx / .p12)", None)?;
    let bytes = read_small(&file)?;
    let password = secret("Пароль PFX (ввод скрыт): ")?;
    let identity = SigningIdentity::import_pkcs12(&bytes, &password)?;
    show_certificate(identity.certificate_der())?;
    Ok(identity)
}
#[derive(Clone)]
enum Location {
    Local(gost_sign_export::discovery::Source),
    #[cfg(feature = "pcsc")]
    Token {
        reader: std::ffi::CString,
        directory: u16,
    },
}
#[derive(Clone)]
struct Selected {
    location: Location,
    certificates: Vec<Vec<u8>>,
    notice: Option<String>,
}
impl Selected {
    fn label(&self) -> String {
        match &self.location {
            Location::Local(source) => source.label(),
            #[cfg(feature = "pcsc")]
            Location::Token { reader, directory } => {
                format!("{} / {directory:04x}", reader.to_string_lossy())
            }
        }
    }
    fn load(&self) -> Result<Container> {
        match &self.location {
            Location::Local(source) => source.load(),
            #[cfg(feature = "pcsc")]
            Location::Token { reader, directory } => {
                gost_sign_export::token::container_with_pin(reader, *directory, || {
                    let pin = secret("PIN пользователя (Enter — отмена, одна попытка): ")?;
                    if pin.is_empty() {
                        return Err(Box::new(Cancelled));
                    }
                    Ok(Zeroizing::new(pin.as_bytes().to_vec()))
                })
            }
        }
    }
    fn show(&self) -> Result<()> {
        println!("Источник: {}", self.label());
        if let Some(notice) = &self.notice {
            println!("{notice}");
        }
        if self.certificates.is_empty() {
            println!("Открытый сертификат недоступен или отсутствует.");
        }
        for (i, cert) in self.certificates.iter().enumerate() {
            println!("Сертификат {}:", i + 1);
            show_certificate(cert)?;
        }
        Ok(())
    }
}
fn local_entries(roots: Option<&[PathBuf]>) -> Vec<Selected> {
    let report = match roots {
        Some(roots) => gost_sign_export::discovery::directories(roots),
        None => gost_sign_export::discovery::system(),
    };
    for notice in report.notices {
        println!("Примечание: {notice}");
    }
    report
        .entries
        .into_iter()
        .map(|e| Selected {
            location: Location::Local(e.source),
            certificates: e.certificates,
            notice: e.notice,
        })
        .collect()
}
fn token_entries() -> Result<Vec<Selected>> {
    #[cfg(feature = "pcsc")]
    {
        let mut entries = Vec::new();
        for reader in gost_sign_export::token::readers()? {
            println!("Поиск на {} (без PIN)…", reader.to_string_lossy());
            let discovered = gost_sign_export::token::discover(&reader, |fid| {
                if fid & 31 == 0 {
                    println!("  Проверка каталогов: {} /256", usize::from(fid - 0x0a00));
                }
            });
            match discovered {
                Ok(found) => {
                    for entry in found {
                        entries.push(Selected {
                            location: Location::Token {
                                reader: reader.clone(),
                                directory: entry.directory,
                            },
                            certificates: entry.certificates,
                            notice: entry.notice,
                        });
                    }
                }
                Err(e) => println!(
                    "{}: {}",
                    reader.to_string_lossy(),
                    gost_sign_export::console_error(e.as_ref())
                ),
            }
        }
        Ok(entries)
    }
    #[cfg(not(feature = "pcsc"))]
    {
        Err("В этой сборке нет PC/SC".into())
    }
}
fn choose_entry(entries: Vec<Selected>) -> Result<Selected> {
    if entries.is_empty() {
        return Err("Контейнеры не найдены. Можно указать папку вручную".into());
    }
    for (i, entry) in entries.iter().enumerate() {
        println!("\n──── Контейнер {} ────", i + 1);
        entry.show()?;
    }
    println!("\n:назад — сохранить прежний выбор и вернуться в меню.");
    let value = prompt("Номер контейнера: ")?;
    let index = value.parse::<usize>()?;
    entries
        .into_iter()
        .nth(index.checked_sub(1).ok_or("Неверный номер контейнера")?)
        .ok_or_else(|| "Неверный номер контейнера".into())
}
fn select_container() -> Result<Selected> {
    println!(
        "1 — Найти контейнеры КриптоПро на компьютере\n2 — Найти контейнеры на Рутокен Lite\n3 — Указать папку контейнера или папку для поиска"
    );
    let source = prompt("Источник [1]: ")?;
    let entries = match source.as_str() {
        "" | "1" => local_entries(None),
        "2" => token_entries()?,
        "3" => {
            let folder = path("Папка", None)?;
            local_entries(Some(&[folder]))
        }
        _ => return Err("Выберите 1, 2 или 3".into()),
    };
    choose_entry(entries)
}
fn confirm_selected(selected: &Selected) -> Result<()> {
    println!("\nВыбранный контейнер:");
    selected.show()?;
    let answer = prompt("Enter — продолжить; :назад — вернуться и сменить контейнер: ")?;
    if !answer.is_empty() {
        return Err(Box::new(Cancelled));
    }
    Ok(())
}
fn selected_certificate(selected: &Selected) -> Result<Vec<u8>> {
    let certs = match &selected.location {
        Location::Local(gost_sign_export::discovery::Source::Directory(folder)) => {
            gost_sign_export::certificates_from_header(&read_small(&folder.join("header.key"))?)?
        }
        #[cfg(windows)]
        Location::Local(_) => selected.certificates.clone(),
        #[cfg(feature = "pcsc")]
        Location::Token { reader, directory } => {
            gost_sign_export::token::certificates(reader, *directory)?
        }
    };
    choose_certificate(&certs).cloned()
}
fn choose_certificate(certs: &[Vec<u8>]) -> Result<&Vec<u8>> {
    if certs.is_empty() {
        return Err("Открытый сертификат не найден".into());
    }
    for (i, cert) in certs.iter().enumerate() {
        println!("\nСертификат {}", i + 1);
        show_certificate(cert)?;
    }
    let index = if certs.len() == 1 {
        1
    } else {
        prompt("Номер сертификата: ")?.parse::<usize>()?
    };
    certs
        .get(index.checked_sub(1).ok_or("Неверный номер сертификата")?)
        .ok_or_else(|| "Неверный номер сертификата".into())
}
fn export_selected_certificate(selected: &Selected) -> Result<()> {
    confirm_selected(selected)?;
    let certificate = selected_certificate(selected)?;
    let output = destination("Новый файл сертификата", Path::new("certificate.cer"))?;
    save(&output, &certificate)
}
fn token_certificates() -> Result<Vec<Vec<u8>>> {
    let selected = choose_entry(token_entries()?)?;
    Ok(vec![selected_certificate(&selected)?])
}

fn migrate(selected: &Selected) -> Result<()> {
    confirm_selected(selected)?;
    let container = selected.load()?;
    let password = if container.source_password_required()? {
        secret("Пароль исходного контейнера КриптоПро: ")?
    } else {
        Zeroizing::new(String::new())
    };
    let key = container.primary_pkcs8(&password)?;
    let certs = container.certificates()?;
    let certificate = choose_certificate(&certs)?;
    let identity = SigningIdentity::import_pkcs8(certificate, &key)?;
    show_certificate(identity.certificate_der())?;
    println!("Соответствие ключа сертификату проверено.");
    let output = destination("Новый файл PFX", Path::new("identity.pfx"))?;
    let password = loop {
        let password = secret("Новый пароль PFX (обязателен): ")?;
        if password.is_empty() {
            println!("Пароль не может быть пустым.");
            continue;
        }
        if *password == *secret("Повторите новый пароль: ")? {
            break password;
        }
        println!("Пароли не совпали. Повторите ввод.");
    };
    save(&output, &identity.export_pkcs12(&password)?)?;
    println!("Для подписи этим PFX нужны только файл и новый пароль. Старый PIN не сохраняется.");
    Ok(())
}
fn sign() -> Result<()> {
    let identity = open_pfx()?;
    let document = path("Документ для подписи", None)?;
    let mut proposed = document.as_os_str().to_os_string();
    proposed.push(".p7s");
    let output = destination("Файл подписи", Path::new(&proposed))?;
    let content = std::fs::read(&document)?;
    save(&output, &identity.sign_cades(&content)?)?;
    println!(
        "Создана отсоединённая CAdES-BES подпись. Передавайте её вместе с исходным документом."
    );
    Ok(())
}
fn verify() -> Result<()> {
    let document = path("Исходный документ", None)?;
    let mut proposed = document.as_os_str().to_os_string();
    proposed.push(".p7s");
    let signature = path("Файл подписи", Some(Path::new(&proposed)))?;
    let valid = gost_sign_cms::verification::verify_detached(
        &std::fs::read(document)?,
        &read_small(&signature)?,
    )
    .map_err(|_| "Подпись повреждена или её формат не поддерживается")?;
    if !valid {
        return Err("Подпись не соответствует документу".into());
    }
    println!(
        "Подпись соответствует документу. Доверие, срок действия и отзыв сертификата не проверялись."
    );
    Ok(())
}
fn export_certificate() -> Result<()> {
    println!(
        "Открытый сертификат (.cer) не содержит закрытого ключа и сам по себе не позволяет подписывать.\n1 — PFX\n2 — Папка контейнера / header.key / сертификат DER\n3 — Рутокен Lite (без PIN)"
    );
    let certs = match prompt("Источник: ")?.as_str() {
        "1" => vec![open_pfx()?.certificate_der().to_vec()],
        "2" => {
            let mut source = path("Папка или файл", None)?;
            if source.is_dir() {
                source.push("header.key");
            }
            let bytes = read_small(&source)?;
            if gost_sign_core::parse_certificate_der(&bytes).is_ok() {
                vec![bytes]
            } else {
                gost_sign_export::certificates_from_header(&bytes)?
            }
        }
        "3" => token_certificates()?,
        _ => return Err("Выберите 1, 2 или 3".into()),
    };
    if certs.is_empty() {
        return Err("Встроенные сертификаты не найдены".into());
    }
    for (i, cert) in certs.iter().enumerate() {
        println!("\nСертификат {}", i + 1);
        show_certificate(cert)?;
    }
    let index = if certs.len() == 1 {
        1
    } else {
        prompt("Номер сертификата: ")?.parse::<usize>()?
    };
    let cert = index
        .checked_sub(1)
        .and_then(|i| certs.get(i))
        .ok_or("Неверный номер сертификата")?;
    let output = destination("Новый файл сертификата", Path::new("certificate.cer"))?;
    save(&output, cert)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        println!("gost-sign {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "gost-sign — подпись и работа с сертификатами\nЗапустите без аргументов для общего меню.\nПодпись и проверка документов; перенос ключа в PFX; экспорт сертификата.\n--list-containers — список локальных контейнеров без PIN.\n--version — версия, --help — справка.\nПароли вводятся скрыто. :назад в обычном поле — отмена; Ctrl+C — выход."
        );
        return Ok(());
    }
    if args.len() == 1 && args[0] == "--list-containers" {
        for entry in local_entries(None) {
            entry.show()?;
        }
        return Ok(());
    }
    if !args.is_empty() {
        return Err("Неизвестные аргументы. Запустите gost-sign --help".into());
    }
    println!(
        "gost-sign {}\nПароли вводятся скрыто. :назад — отмена действия; Ctrl+C — выход.\nПути с пробелами можно вставлять в кавычках.",
        env!("CARGO_PKG_VERSION")
    );
    let mut selected: Option<Selected> = None;
    loop {
        if let Some(current) = &selected {
            println!("\nТекущий контейнер: {}", current.label());
            for cert in &current.certificates {
                show_certificate(cert)?;
            }
        } else {
            println!("\nКонтейнер не выбран.");
        }
        println!(
            "\n1 — Подписать документ из PFX\n2 — Проверить подпись\n3 — Экспорт выбранного контейнера в PFX\n4 — Экспорт сертификата из файла/PFX\n5 — Выбрать или сменить контейнер\n6 — Экспорт сертификата выбранного контейнера\n0 — Выход"
        );
        let action = match prompt("Выберите действие: ") {
            Ok(s) => s,
            Err(e) if e.is::<Cancelled>() => continue,
            Err(e) if eof(e.as_ref()) => return Ok(()),
            Err(e) => return Err(e),
        };
        let result = match action.as_str() {
            "0" => return Ok(()),
            "1" => sign(),
            "2" => verify(),
            "3" => {
                if let Some(current) = &selected {
                    migrate(current)
                } else {
                    Err("Сначала выберите контейнер (пункт 5)".into())
                }
            }
            "4" => export_certificate(),
            "5" => match select_container() {
                Ok(entry) => {
                    selected = Some(entry);
                    println!("Выбор сохранён. Теперь выберите действие.");
                    Ok(())
                }
                Err(e) => Err(e),
            },
            "6" => {
                if let Some(current) = &selected {
                    export_selected_certificate(current)
                } else {
                    Err("Сначала выберите контейнер (пункт 5)".into())
                }
            }
            _ => {
                println!("Введите номер от 0 до 6.");
                continue;
            }
        };
        if let Err(e) = result {
            if eof(e.as_ref()) {
                return Ok(());
            }
            if e.is::<Cancelled>() {
                println!("Действие отменено.");
            } else {
                eprintln!("Ошибка: {}", gost_sign_export::console_error(e.as_ref()));
            }
        }
    }
}
fn eof(e: &(dyn Error + 'static)) -> bool {
    e.downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof)
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Ошибка: {}", gost_sign_export::console_error(e.as_ref()));
            std::process::ExitCode::FAILURE
        }
    }
}
