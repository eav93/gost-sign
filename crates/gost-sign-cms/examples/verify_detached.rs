//! Verify a local DER CMS and exact detached content without printing certificate identity.
use std::{env, fs, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 2 {
        eprintln!("Usage: verify_detached <content-file> <signature.der>");
        return ExitCode::from(2);
    }
    let result = (|| -> Result<bool, Box<dyn std::error::Error>> {
        let content = fs::read(&args[0])?;
        let signature = fs::read(&args[1])?;
        Ok(gost_sign_cms::verification::verify_detached(
            &content, &signature,
        )?)
    })();
    match result {
        Ok(true) => {
            println!("Signature and content binding valid (certificate trust not checked)");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("Signature or content/certificate binding mismatch");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("Cannot verify: {error}");
            ExitCode::from(2)
        }
    }
}
