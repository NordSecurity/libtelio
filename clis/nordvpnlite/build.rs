use std::env;
use std::process::Command;

fn main() {
    let commit_sha = env::var("LIBTELIO_COMMIT_SHA").unwrap_or_else(|_| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout)
                        .ok()
                        .map(|s| format!("dev-{}", s.trim()))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "dev-unknown".to_string())
    });
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=LIBTELIO_COMMIT_SHA={}", commit_sha);
    println!("cargo:rustc-env=BUILD_PROFILE={}", profile);

    println!("cargo:rerun-if-env-changed=LIBTELIO_COMMIT_SHA");
    println!("cargo:rerun-if-env-changed=PROFILE");
}
