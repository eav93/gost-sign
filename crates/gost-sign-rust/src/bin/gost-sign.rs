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
    println!(
        "Владелец: {}\nИздатель: {}\nСрок: {} — {}",
        tbs.subject(),
        tbs.issuer(),
        tbs.validity().not_before,
        tbs.validity().not_after
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
#[cfg(feature = "pcsc")]
fn with_token<T>(f: impl FnOnce(&std::ffi::CStr, u16) -> Result<T>) -> Result<T> {
    let readers = gost_sign_export::token::readers()?;
    if readers.is_empty() {
        return Err("Рутокен не найден. Подключите его и проверьте службу PC/SC".into());
    }
    let index = if readers.len() == 1 {
        println!("Считыватель: {}", readers[0].to_string_lossy());
        1
    } else {
        for (i, r) in readers.iter().enumerate() {
            println!("{} — {}", i + 1, r.to_string_lossy());
        }
        prompt("Номер считывателя: ")?.parse::<usize>()?
    };
    let reader = index
        .checked_sub(1)
        .and_then(|i| readers.get(i))
        .ok_or("Неверный номер считывателя")?;
    let directory = prompt("Каталог контейнера на токене, hex [0a00; Enter — оставить]: ")?;
    let fid = if directory.is_empty() {
        0x0a00
    } else {
        u16::from_str_radix(&directory, 16)?
    };
    f(reader, fid)
}
fn token_container() -> Result<Container> {
    #[cfg(feature = "pcsc")]
    {
        with_token(|reader, fid| {
            gost_sign_export::token::container_with_pin(reader, fid, || {
                let pin = secret("PIN пользователя Рутокена (ввод скрыт, одна попытка): ")?;
                Ok(Zeroizing::new(pin.as_bytes().to_vec()))
            })
        })
    }
    #[cfg(not(feature = "pcsc"))]
    {
        Err("В этой сборке нет PC/SC. Используйте полную сборку программы".into())
    }
}
fn token_certificates() -> Result<Vec<Vec<u8>>> {
    #[cfg(feature = "pcsc")]
    {
        with_token(gost_sign_export::token::certificates)
    }
    #[cfg(not(feature = "pcsc"))]
    {
        Err("В этой сборке нет PC/SC. Используйте полную сборку программы".into())
    }
}
fn migrate() -> Result<()> {
    println!(
        "Перенос ключа и сертификата в защищённый PFX. Исходный контейнер сохраняется.\n1 — Папка контейнера КриптоПро (.000)\n2 — Подключённый Рутокен Lite"
    );
    let container = match prompt("Источник: ")?.as_str() {
        "1" => Container::from_directory(&path("Папка контейнера (.000)", None)?)?,
        "2" => token_container()?,
        _ => return Err("Выберите 1 или 2".into()),
    };
    let password = if container.source_password_required()? {
        secret("Пароль исходного контейнера КриптоПро: ")?
    } else {
        Zeroizing::new(String::new())
    };
    let key = container.primary_pkcs8(&password)?;
    let certs = container.certificates()?;
    if certs.len() != 1 {
        return Err("Для переноса пока требуется ровно один встроенный сертификат".into());
    }
    let identity = SigningIdentity::import_pkcs8(&certs[0], &key)?;
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
            "gost-sign — подпись и работа с сертификатами\nЗапустите без аргументов для общего меню.\nПодпись и проверка документов; перенос ключа в PFX; экспорт сертификата.\n--version — версия, --help — справка.\nПароли вводятся скрыто. :назад в обычном поле — отмена; Ctrl+C — выход."
        );
        return Ok(());
    }
    if !args.is_empty() {
        return Err("Неизвестные аргументы. Запустите gost-sign --help".into());
    }
    println!(
        "gost-sign {}\nПароли вводятся скрыто. :назад — отмена действия; Ctrl+C — выход.\nПути с пробелами можно вставлять в кавычках.",
        env!("CARGO_PKG_VERSION")
    );
    loop {
        println!(
            "\n1 — Подписать документ\n2 — Проверить подпись\n3 — Перенести ключ и сертификат в PFX\n4 — Экспортировать открытый сертификат (.cer)\n0 — Выход"
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
            "3" => migrate(),
            "4" => export_certificate(),
            _ => {
                println!("Введите номер от 0 до 4.");
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
