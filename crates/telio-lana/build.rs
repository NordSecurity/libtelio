#[allow(unwrap_check)]
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "windows" {
        if let Some(path) = std::option_env!("OUT_DIR") {
            println!("cargo:rustc-link-search={}", path);
        }
    }
}
