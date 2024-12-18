use std::{fs::OpenOptions, io::Write, process};

use tracing::warn;

use crate::TeliodError;

use super::constants::PID_FILE;

pub struct PidFile;

impl PidFile {
    pub async fn new() -> Result<Self, TeliodError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(PID_FILE)?;
        writeln!(file, "{}", process::id())?;
        Ok(Self)
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(PID_FILE) {
            warn!("Failed to remove PID file: {}", e);
        }
    }
}
