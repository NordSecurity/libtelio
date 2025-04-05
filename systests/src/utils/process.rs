use std::process::{Command, ExitStatus};

#[derive(Debug)]
pub enum ProcessExecError {
    FailedToRun(std::io::Error),
    FailedDuringRun(ExitStatus, String),
}

pub fn run_command(args: &[&str], allowed_errors: &[&str]) -> Result<String, ProcessExecError> {
    let full_command = args.join(" ");
    let res = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(ProcessExecError::FailedToRun)?;
    let stderr =
        String::from_utf8(res.stderr).expect("Command output shhould be valid utf8 string");
    if res.status.success() || allowed_errors.iter().any(|err| stderr.contains(err)) {
        println!("Successfully executed '{full_command}'");
        Ok(String::from_utf8(res.stdout).expect("Command output should be valid utf8 string"))
    } else {
        let err = ProcessExecError::FailedDuringRun(res.status, stderr);
        println!("Failed to execute '{full_command}' with error {err:?}");
        Err(err)
    }
}
