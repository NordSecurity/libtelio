use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn check_git_secrets() -> Result<()> {
    match Command::new("git").args(["secrets", "--list"]).output() {
        Ok(output) => match output.status.code() {
            Some(0) => {
                let output = String::from_utf8(output.stdout)?;
                for line in output.lines() {
                    if line.ends_with("llt-secrets/secrets")
                        || line.ends_with("llt-secrets\\secrets")
                    {
                        return Ok(());
                    }
                }
                bail!("llt-secrets not found in git-secrets providers list!")
            }
            Some(1) => {
                let stderr = String::from_utf8(output.stderr)?;
                if let Some(true) = stderr
                    .lines()
                    .next()
                    .map(|line| line.starts_with("git: 'secrets' is not a git command."))
                {
                    bail!("git-secrets not installed!")
                }
                bail!("llt-secrets not found in git-secrets providers list!")
            }
            _ => {
                bail!(
                    "git-secrets failed with status code: {}\nstdout:\n{}\nstderr:\n{}\n",
                    output.status,
                    String::from_utf8(output.stdout).unwrap_or_default(),
                    String::from_utf8(output.stderr).unwrap_or_default(),
                )
            }
        },
        Err(error) => {
            bail!("git failed with unexpected error: {error}")
        }
    }
}

fn get_git_path() -> Result<PathBuf> {
    match Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
    {
        Ok(output) => Ok(String::from_utf8(output.stdout)?.trim().into()),
        Err(_) => {
            bail!("Failed to get git directory. git rev-parse --git-dir failed.")
        }
    }
}

fn check_git_hooks() -> Result<()> {
    let hooks_path = get_git_path()
        .context("Checking git hooks failed")?
        .join("hooks");
    let hooks = vec![
        hooks_path.join("commit-msg"),
        hooks_path.join("pre-commit"),
        hooks_path.join("prepare-commit-msg"),
    ];
    for hook in hooks {
        if !hook.exists() {
            bail!("Hook {:?} not installed", hook)
        }
    }
    Ok(())
}

fn verify_llt_secrets() {
    if !env::var("GITLAB_CI")
        .or(env::var("GITHUB_ACTIONS"))
        .is_ok_and(|value| value == "true")
    {
        if env::var("BYPASS_LLT_SECRETS").is_ok() {
            println!("cargo:warning=BYPASS_LLT_SECRETS IS SET, COMMIT CAREFULLY!!");
            return;
        }

        println!("cargo:rerun-if-changed=./crates");
        println!("cargo:rerun-if-changed=./src");

        #[allow(clippy::panic)]
        match check_git_secrets().and_then(|_| check_git_hooks()) {
            Ok(_) => {}
            Err(err) => {
                panic!(
                    "Secrets scanning seems to be missing or misconfigured. Either run checkout scripts \
                    or run with BYPASS_LLT_SECRETS environment variable set\nError: {:#}",
                    err
                );
            }
        }
    }
}

fn main() -> Result<()> {
    uniffi::generate_scaffolding("./src/libtelio.udl")?;

    verify_llt_secrets();

    let target_os = env::var("CARGO_CFG_TARGET_OS")?;

    if target_os == "android" {
        let pkg_name = env!("CARGO_PKG_NAME");
        let soname = format!("lib{}.so", pkg_name);
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,max-page-size=16384,-soname,{}", soname);
    }

    #[cfg(windows)]
    if target_os == "windows" {
        winres::WindowsResource::new()
            .set("LegalCopyright", "Nord Security")
            .compile()?;
    }

    Ok(())
}
