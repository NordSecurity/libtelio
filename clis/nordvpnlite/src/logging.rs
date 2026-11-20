use std::{io, path::Path};

use telio_core::logging::LOG_CENSOR;
use tracing::level_filters::LevelFilter;
use tracing_appender::{
    non_blocking::{NonBlocking, WorkerGuard},
    rolling::{Builder, RollingFileAppender, Rotation},
};
use tracing_subscriber::{fmt::MakeWriter, reload, Layer, Registry};

use crate::NordVpnLiteError;

type DynLayer = Box<dyn Layer<Registry> + Send + Sync>;

pub struct LoggingHandle {
    _worker_guard: WorkerGuard,
    fmt_layer_reload_handle: reload::Handle<DynLayer, Registry>,
    filter_reload_handle: reload::Handle<LevelFilter, Registry>,
}

fn build_appender<P: AsRef<Path>>(
    log_file_path: P,
    log_file_count: usize,
) -> Result<RollingFileAppender, NordVpnLiteError> {
    Builder::new()
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
        })?)
        .map_err(Into::into)
}

/// Passes every formatted log line through libtelio's `LOG_CENSOR` before writing it.
#[derive(Clone)]
struct CensoredWriter<W>(W);

impl<W: io::Write> io::Write for CensoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // fmt layer writes each formatted event with a single write_all call
        let line = String::from_utf8_lossy(buf).into_owned();
        self.0.write_all(LOG_CENSOR.censor_logs(line).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for CensoredWriter<NonBlocking> {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn build_fmt_layer(writer: NonBlocking) -> DynLayer {
    Box::new(
        tracing_subscriber::fmt::layer()
            .with_writer(CensoredWriter(writer))
            .with_ansi(false)
            .with_line_number(true)
            .with_level(true),
    )
}

pub fn setup_logging<P: AsRef<Path>>(
    log_file_path: P,
    log_level: LevelFilter,
    log_file_count: usize,
) -> Result<LoggingHandle, NordVpnLiteError> {
    use tracing_subscriber::prelude::*;

    let appender = build_appender(&log_file_path, log_file_count)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let fmt_layer: DynLayer = build_fmt_layer(writer);

    let (layer_reload, fmt_layer_reload_handle) = reload::Layer::new(fmt_layer);
    let (filter_reload, filter_reload_handle) = reload::Layer::new(log_level);

    let subscriber = Registry::default().with(layer_reload.with_filter(filter_reload));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| NordVpnLiteError::TracingError(e.to_string()))?;

    Ok(LoggingHandle {
        _worker_guard: guard,
        fmt_layer_reload_handle,
        filter_reload_handle,
    })
}

pub fn reload_logging<P: AsRef<Path>>(
    handle: &mut LoggingHandle,
    log_file_path: P,
    log_level: LevelFilter,
    log_file_count: usize,
) -> Result<(), NordVpnLiteError> {
    let appender = build_appender(&log_file_path, log_file_count)?;
    let (new_writer, new_guard) = tracing_appender::non_blocking(appender);
    let new_layer: DynLayer = build_fmt_layer(new_writer);

    handle
        .filter_reload_handle
        .modify(|level| *level = log_level)
        .map_err(|e| NordVpnLiteError::TracingError(e.to_string()))?;

    handle
        .fmt_layer_reload_handle
        .modify(|layer| *layer = new_layer)
        .map_err(|e| NordVpnLiteError::TracingError(e.to_string()))?;

    handle._worker_guard = new_guard;

    Ok(())
}

#[macro_export]
macro_rules! nordvpnlite_logstd_warn {
    ($($arg:tt)*) => {{
        ::tracing::warn!($($arg)*);
        ::std::eprintln!("WARNING: {}", ::std::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! nordvpnlite_logstd_error {
    ($($arg:tt)*) => {{
        ::tracing::error!($($arg)*);
        ::std::eprintln!("ERROR: {}", ::std::format_args!($($arg)*));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_censored_writer_shortens_public_keys() {
        let mut writer = CensoredWriter(Vec::new());
        let line = b"Node connected: peer (JkgUJU4d25dRV/URMXlnOlcVF2Qbk3FuVpu4O0Lt9E4=)\n";

        assert_eq!(line.len(), writer.write(line).unwrap());
        assert_eq!(
            "Node connected: peer (JkgU...9E4=)\n",
            String::from_utf8(writer.0).unwrap()
        );
    }
}
