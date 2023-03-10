use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("std::io::error {0}")]
    StdIo(#[from] std::io::Error),

    #[error("invalid exit code {0:?}")]
    ExitCode(Option<i32>),
}

pub trait ExecutableCommand {
    fn execute(&mut self) -> Result<(), ExecuteError>;
}

impl ExecutableCommand for Command {
    fn execute(&mut self) -> Result<(), ExecuteError> {
        let status = self.status()?;
        if status.success() {
            Ok(())
        } else {
            Err(ExecuteError::ExitCode(status.code()))
        }
    }
}
