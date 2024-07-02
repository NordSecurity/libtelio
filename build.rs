use anyhow::Result;
use std::{env, path::Path};

fn build() -> Result<cc::Build> {
    if !env::var("GITLAB_CI")
        .or(env::var("GITHUB_ACTIONS"))
        .is_ok_and(|value| value == "true")
    {
        println!("cargo:rerun-if-changed=.prepared_llt_secrets");
        println!("cargo:rerun-if-env-changed=BYPASS_LLT_SCAN");

        // Check for sec scan
        let prepared_path = Path::new(".prepared_llt_secrets");
        #[allow(clippy::panic)]
        if !prepared_path.is_file() {
            match env::var("BYPASS_LLT_SECRETS") {
                Ok(_) => println!("cargo:warning=BYPASS_LLT_SCAN IS SET, COMMIT CAREFULLY!!"),
                Err(_) => {
                    panic!("Hooks not found, either run checkout scripts or run with BYPASS_LLT_SECRETS environment variable set");
                }
            }
        }
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS")?;

    let mut build = cc::Build::new();
    if target_os == "windows" {
        // -lssp is required when source fortification is enabled for Windows. Since -lssp is a
        // dynamic library, its very undesirable and right now I'm not in the mood to try and
        // find a proper solution. So just skip source fortification for Windows for now.
        // https://github.com/msys2/MINGW-packages/issues/5868
    } else {
        build.flag("-D_FORTIFY_SOURCE=2");
    }
    Ok(build)
}

fn main() -> Result<()> {
    uniffi::generate_scaffolding("./src/libtelio.udl")?;

    let target_os = env::var("CARGO_CFG_TARGET_OS")?;

    {
        let path = "suppress_source_fortification_check.c";
        println!("cargo:rerun-if-changed={}", &path);
        // The culprit for breaking the MSVC build is "-Werror", because cl.exe requires a numeric parameter.
        if cfg!(target_env = "msvc") {
            build()?
                .file(path)
                .compile("suppressSourceFortificationCheck");
        } else {
            build()?
                .file(path)
                .flag("-Werror")
                .flag("-O3")
                .compile("suppressSourceFortificationCheck");
        }
    }

    if target_os == "android" {
        let pkg_name = env!("CARGO_PKG_NAME");
        let soname = format!("lib{}.so", pkg_name);
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,{}", soname);
    }

    #[cfg(windows)]
    if target_os == "windows" {
        winres::WindowsResource::new()
            .set("LegalCopyright", "Nord Security")
            .compile()?;
    }

    Ok(())
}
