//! Подпись файла из PFX без внешнего провайдера.
use std::{error::Error, io::Write, path::Path};
use zeroize::Zeroizing;
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("Использование: sign_pfx КЛЮЧ.pfx ДОКУМЕНТ НОВАЯ_ПОДПИСЬ.p7s".into());
    }
    let password = Zeroizing::new(rpassword::prompt_password("Пароль PFX: ")?);
    let identity =
        gost_sign_rust::SigningIdentity::import_pkcs12(&std::fs::read(&args[0])?, &password)?;
    let document = std::fs::read(&args[1])?;
    let signature = identity.sign_cades(&document)?;
    if !gost_sign_cms::verification::verify_detached(&document, &signature)? {
        return Err("Проверка созданной подписи не прошла".into());
    }
    let destination = Path::new(&args[2]);
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    output.write_all(&signature)?;
    output.as_file().sync_all()?;
    output.persist_noclobber(destination).map_err(|e| e.error)?;
    println!("Подпись сохранена: {}", destination.display());
    Ok(())
}
