use std::env;
use std::process::Command;

#[allow(unwrap_check)]
fn main() {
    // wireguard-go is currently built on Windows only
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "windows" {
        panic!("Only windows supported as target! {}", target_os);
    }

    // build.rs files are built to run as binaries on the host, so the [cfg(target_os)] here is actually the host OS
    #[cfg(target_os = "windows")]
    let host_os = "windows";
    #[cfg(not(target_os = "windows"))]
    let host_os = "other";

    println!("cargo:rerun-if-changed=./");

    match std::env::var("OUT_DIR") {
        Ok(path) => {
            println!("cargo:rustc-link-search={}", path)
        }
        Err(_e) => {}
    }

    println!("cargo:rustc-link-lib=static=wireguard-go");

    // At this stage, target_arch will be used only in windows-native build 
    let target_arch = {
        match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => {
                panic!("Incompatible CARGO_CFG_TARGET_ARCH value!");
            }
        }
    };

    // Cannot execute PowerShell scripts on Windows the same way Shell scripts are run on Linux.
    // Here, PowerShell needs to be called as the actual command and the script path be passed as argument.
    if host_os == "windows" {
        let output = Command::new("powershell.exe")
            .current_dir("wireguard-go")
            .args(&["./build.ps1", target_arch])
            .output()
            .expect("failed to build");
        if !output.status.success() {
            panic!(
                "\nSTDERR: {}\n STDOUT: {}\n",
                std::str::from_utf8(&output.stderr).unwrap(),
                std::str::from_utf8(&output.stdout).unwrap()
            );
        }
    } else {
        let output = Command::new("./build.sh")
            .current_dir("wireguard-go")
            .arg(target_os)
            .output()
            .expect("failed to build");
        if !output.status.success() {
            panic!(
                "\nSTDERR: {}\n STDOUT: {}\n",
                std::str::from_utf8(&output.stderr).unwrap(),
                std::str::from_utf8(&output.stdout).unwrap()
            );
        }
    }

    // Workaround for hanging wireguard-go due to missing Go runtime init when building with MSVC toolchain.
    let mut build = cc::Build::new();

    println!("cargo:rerun-if-changed=workaround_msvc_static_go_runtime_init.c");
    build
        .file("workaround_msvc_static_go_runtime_init.c")
        .compile("workaroundMsvcStaticGoRuntimeInit");
}
