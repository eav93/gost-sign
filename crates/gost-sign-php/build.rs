fn main() {
    // Zend symbols are resolved by the host PHP process when the module loads.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}
