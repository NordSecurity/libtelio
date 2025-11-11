use std::path::Path;

use tracing::{level_filters::LevelFilter, Level};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{Builder, Rotation},
};

use crate::NordVpnLiteError;

pub async fn setup_logging<P: AsRef<Path>>(
    log_file_path: P,
    log_level: LevelFilter,
    log_file_count: usize,
) -> Result<WorkerGuard, NordVpnLiteError> {
    let log_appender = Builder::new()
        .filename_prefix(
            log_file_path
                .as_ref()
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| NordVpnLiteError::InvalidConfigOption {
                    key: "log_file_path".to_owned(),
                    msg: "is not valid UTF-8".to_owned(),
                    value: log_file_path.as_ref().to_string_lossy().into_owned(),
                })?,
        )
        .rotation(if log_file_count == 0 {
            Rotation::NEVER
        } else {
            Rotation::DAILY
        })
        .max_log_files(log_file_count)
        .build(log_file_path.as_ref().parent().ok_or_else(|| {
            NordVpnLiteError::InvalidConfigOption {
                key: "log_file_path".to_owned(),
                msg: "needs to contain both directory and file name".to_owned(),
                value: log_file_path.as_ref().to_string_lossy().into_owned(),
            }
        })?)?;

    let (non_blocking_writer, tracing_worker_guard) = tracing_appender::non_blocking(log_appender);
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    Ok(tracing_worker_guard)
}
