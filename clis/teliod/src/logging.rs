use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use tracing::level_filters::LevelFilter;
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{Builder, Rotation},
};

use crate::TeliodError;

pub async fn setup_logging(
    log_file_path: &str,
    log_level: LevelFilter,
    log_file_count: usize,
) -> Result<WorkerGuard, TeliodError> {
    let log_file_pathbuf = PathBuf::from_str(log_file_path).map_err(|e| {
        TeliodError::InvalidConfigOption(
            "log_file_path".to_owned(),
            e.to_string(),
            log_file_path.to_string(),
        )
    })?;

    let empty: &Path = Path::new("");

    let (log_dir, log_file) = match (log_file_pathbuf.parent(), log_file_pathbuf.file_name()) {
        (Some(log_dir), Some(file_name)) if log_dir != empty && file_name != empty => {
            (log_dir, file_name)
        }
        _ => {
            return Err(TeliodError::InvalidConfigOption(
                "log_file_path".to_owned(),
                "log_file_path needs to contain both directory and file name".to_owned(),
                log_file_path.to_owned(),
            ))
        }
    };

    let log_appender = Builder::new()
        .filename_prefix(log_file.to_string_lossy())
        .rotation(if log_file_count == 0 {
            Rotation::NEVER
        } else {
            Rotation::DAILY
        })
        .max_log_files(log_file_count)
        .build(log_dir)?;

    let (non_blocking_writer, tracing_worker_guard) = tracing_appender::non_blocking(log_appender);
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    Ok(tracing_worker_guard)
}
