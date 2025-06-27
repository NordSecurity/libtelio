use anyhow::Result;
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let package_name = env::var("CARGO_PKG_NAME")?;
    let output_file = target_dir()?
        .join("include")
        .join(format!("{}.h", package_name.replace('-', "_")));

    cbindgen::generate(crate_dir)?.write_to_file(&output_file);

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/chain.rs");
    println!("cargo:rerun-if-changed=src/error.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    Ok(())
}

// Helper function to get the target directory
fn target_dir() -> Result<PathBuf> {
    Ok(if let Ok(target) = env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target)
    } else {
        PathBuf::from(env::var("OUT_DIR")?)
    })
}
