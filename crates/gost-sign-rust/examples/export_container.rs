//! Экспорт локального контейнера. Пароли вводятся скрыто.
use std::{error::Error, io::Write, path::Path};
use zeroize::Zeroizing;
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("Использование: export_container ПАПКА.000 НОВЫЙ.pfx".into());
    }
    let container = gost_sign_export::container::Container::from_directory(Path::new(&args[0]))?;
    let password = if container.source_password_required()? {
        Zeroizing::new(rpassword::prompt_password(
            "Пароль исходного контейнера (Enter — если пароль не установлен): ",
        )?)
    } else {
        Zeroizing::new(String::new())
    };
    let key = container.primary_pkcs8(&password)?;
    let certs = container.certificates()?;
    if certs.len() != 1 {
        return Err("Требуется один встроенный сертификат".into());
    }
    let identity = gost_sign_rust::SigningIdentity::import_pkcs8(&certs[0], &key)?;
    let new_password = Zeroizing::new(rpassword::prompt_password("Новый пароль PFX: ")?);
    let repeated = Zeroizing::new(rpassword::prompt_password("Повторите пароль: ")?);
    if new_password.is_empty() || *new_password != *repeated {
        return Err("Пароли пусты или не совпадают".into());
    }
    let pfx = identity.export_pkcs12(&new_password)?;
    let destination = Path::new(&args[1]);
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    output.write_all(&pfx)?;
    output.as_file().sync_all()?;
    output.persist_noclobber(destination).map_err(|e| e.error)?;
    println!("PFX сохранён: {}", destination.display());
    Ok(())
}
