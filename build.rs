use anyhow::{anyhow, Context, Result};
use std::{
    collections::HashSet,
    env,
    fs::File,
    io::{self, BufRead, BufReader},
    iter::FromIterator,
    path::Path,
};

fn build() -> Result<cc::Build> {
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

fn lines_from_file(filename: &str) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

fn abspath(path: &str) -> Option<String> {
    let can_path = std::fs::canonicalize(path).ok()?;
    can_path.into_os_string().into_string().ok()
}

// Compile bindings file and enforce bindings export
fn compile_and_enforce_bindings_export(target_os: &str, lang_wrapper: &str) -> Result<()> {
    let path = format!(
        "ffi/bindings/{target_os}/wrap/{lang_wrapper}.c",
        target_os = target_os,
        lang_wrapper = lang_wrapper
    );
    println!("cargo:rerun-if-changed={}", &path);
    build()?.file(&path).compile(lang_wrapper);

    // For Microsoft link.exe, each exported function must be specified via /export: option.
    // For GNU LD, a structured list of exported functions must be passed in a file via --dynamic-list= option.
    if cfg!(target_env = "msvc") {
        let exports_list_msvc = format!(
            "ffi/bindings/{target_os}/wrap/{lang_wrapper}.msvc_exports.lst",
            target_os = target_os,
            lang_wrapper = lang_wrapper
        );
        if Path::new(&exports_list_msvc).exists() {
            let exported_symbols = lines_from_file(&exports_list_msvc)
                .with_context(|| format!("Could not find {}", exports_list_msvc))?;
            for export_sym in exported_symbols {
                println!("cargo:rustc-link-arg=/export:{}", export_sym);
            }
        }
    } else {
        let exports_list_gnuld = format!(
            "ffi/bindings/{target_os}/wrap/{lang_wrapper}.gnuld_exports.lst",
            target_os = target_os,
            lang_wrapper = lang_wrapper
        );
        // LD requires an absolute path here. Also, LD does not accept empty structures!
        // If no additional exports are required, such as with Linux and Golang, then don't pass a --dynamic-list!
        if Path::new(&exports_list_gnuld).exists() {
            println!(
                "cargo:rustc-link-arg=-Wl,--dynamic-list={}",
                abspath(&exports_list_gnuld).ok_or_else(|| anyhow!(
                    "failed to get absolute path for '{}'",
                    exports_list_gnuld
                ))?
            );
        }
    }

    if target_os == "android" {
        println!(
            "cargo:rustc-link-arg=-Wl,--whole-archive -l{}",
            lang_wrapper
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;

    let langs: HashSet<&str> = HashSet::from_iter(["GO", "JAVA", "CS"].iter().copied());
    let ffis = env::var("FFI").unwrap_or_default();

    let mut ffi: HashSet<&str> = ffis.split(',').filter(|c| langs.contains(c)).collect();
    if ffi.is_empty() {
        match &*target_os {
            "linux" => {
                ffi.insert("GO");
            }
            "android" => {
                ffi.insert("JAVA");
            }
            "windows" => {
                ffi.insert("CS");
            }
            _ => (),
        };
    }

    #[cfg(not(tarpaulin))] // GO FFI fails to compile for tarpaulin (its not needed)
    if ffi.contains(&"GO") {
        compile_and_enforce_bindings_export(&target_os, "go_wrap")?;
    }
    if ffi.contains(&"JAVA") {
        compile_and_enforce_bindings_export(&target_os, "java_wrap")?;
    }
    if ffi.contains(&"CS") {
        compile_and_enforce_bindings_export(&target_os, "csharp_wrap")?;
    }

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

    Ok(())
}
