#![cfg(feature = "cli")]
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn run(input: &str, dir: &std::path::Path) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gost-sign"))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("input");
    child.wait_with_output().expect("output")
}
#[test]
fn exports_certificate_with_unicode_paths_and_refuses_overwrite() {
    let dir = tempfile::tempdir().expect("temp");
    let cert = include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
    std::fs::write(dir.path().join("исходный сертификат.der"), cert).expect("fixture");
    let output = run("4\n2\n\"исходный сертификат.der\"\n\n0\n", dir.path());
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dir.path().join("certificate.cer")).expect("export"),
        cert
    );
    let output = run("4\n2\nисходный сертификат.der\n\n0\n", dir.path());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Файл уже существует"));
    assert_eq!(
        std::fs::read(dir.path().join("certificate.cer")).expect("export"),
        cert
    );
}
#[test]
fn verification_rejects_changed_content_and_menu_handles_cancel_eof() {
    let dir = tempfile::tempdir().expect("temp");
    std::fs::write(
        dir.path().join("document"),
        include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-content.bin"),
    )
    .expect("content");
    std::fs::write(
        dir.path().join("document.p7s"),
        include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-cades.der"),
    )
    .expect("signature");
    let output = run("2\ndocument\n\n2\n:назад\nwrong\n0\n", dir.path());
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Подпись соответствует документу"));
    assert!(text.contains("Действие отменено"));
    assert!(text.contains("Введите номер от 0 до 6"));
    std::fs::write(dir.path().join("document"), b"changed").expect("modify");
    let output = run("2\ndocument\n\n", dir.path());
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Подпись не соответствует документу"));
    assert!(run("", dir.path()).status.success());
}

#[test]
fn selection_can_be_changed_and_cancel_keeps_previous_container() {
    use der::{Encode, Tag, TagNumber, asn1::AnyRef};
    let dir = tempfile::tempdir().expect("temp");
    let root = dir.path().join("containers");
    let cert = include_bytes!("../../gost-sign-cms/tests/fixtures/synthetic-certificate.der");
    let mut second = cert.to_vec();
    *second.last_mut().expect("signature") ^= 1;
    for (name, certificate) in [("a.000", cert.as_slice()), ("b.000", second.as_slice())] {
        let path = root.join(name);
        std::fs::create_dir_all(&path).expect("dir");
        let field = AnyRef::new(
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(5),
            },
            certificate,
        )
        .expect("field")
        .to_der()
        .expect("DER");
        let mut body = AnyRef::new(Tag::Sequence, &field)
            .expect("seq")
            .to_der()
            .expect("DER");
        body.extend([4, 4, 0, 0, 0, 0]);
        let header = AnyRef::new(Tag::Sequence, &body)
            .expect("header")
            .to_der()
            .expect("DER");
        std::fs::write(path.join("header.key"), header).expect("write header");
    }
    let input = "5\n3\ncontainers\n1\n6\n\nfirst.cer\n5\n3\ncontainers\n2\n6\n\nsecond.cer\n5\n:назад\n6\n\nthird.cer\n0\n";
    let output = run(input, dir.path());
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(dir.path().join("first.cer")).expect("first"),
        cert
    );
    assert_eq!(
        std::fs::read(dir.path().join("second.cer")).expect("second"),
        second
    );
    assert_eq!(
        std::fs::read(dir.path().join("third.cer")).expect("third"),
        second
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Текущий контейнер:"));
}
