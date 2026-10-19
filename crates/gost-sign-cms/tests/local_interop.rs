//! Opt-in interoperability check: public artifacts stay outside the repository.
use gost_sign_cms::verification::verify_detached;
#[test]
#[ignore = "requires GOST_INTEROP_CONTENT and GOST_INTEROP_SIGNATURE public fixture paths"]
fn externally_generated_signature_and_tampering() {
    let content = std::fs::read(std::env::var_os("GOST_INTEROP_CONTENT").expect("content path"))
        .expect("read public content");
    let cms = std::fs::read(std::env::var_os("GOST_INTEROP_SIGNATURE").expect("signature path"))
        .expect("read public CMS");
    assert_eq!(verify_detached(&content, &cms), Ok(true));
    let mut changed_content = content.clone();
    changed_content.push(0);
    assert_eq!(verify_detached(&changed_content, &cms), Ok(false));
    if !content.is_empty() {
        changed_content = content.clone();
        changed_content[0] ^= 1;
        assert_eq!(verify_detached(&changed_content, &cms), Ok(false));
        assert_eq!(
            verify_detached(&content[..content.len() - 1], &cms),
            Ok(false)
        );
    }
    let mut changed_signature = cms.clone();
    *changed_signature.last_mut().expect("CMS octet") ^= 1;
    assert_eq!(verify_detached(&content, &changed_signature), Ok(false));
    let mut trailing = cms;
    trailing.push(0);
    assert!(verify_detached(&content, &trailing).is_err());
}
