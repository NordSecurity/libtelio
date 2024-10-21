use std::{
    io::{self, ErrorKind},
    str::from_utf8,
    sync::{Arc, Mutex},
};

use telio_utils::log_censor::LogCensor;

use once_cell::sync::Lazy;

use tracing::{level_filters::LevelFilter, Subscriber};
use tracing_subscriber::{
    fmt::{self, FormatEvent, FormatFields, MakeWriter},
    layer::SubscriberExt,
    registry::LookupSpan,
};

use crate::{TelioLogLevel, TelioLoggerCb};

/// Build a tracing subscriber for use in ffi
pub fn build_subscriber(
    log_level: crate::TelioLogLevel,
    logger: Box<dyn TelioLoggerCb>,
) -> impl Subscriber {
    tracing_subscriber::registry()
        .with(LevelFilter::from_level(log_level.into()))
        .with(
            fmt::layer()
                .event_format(TelioEventFmt)
                .with_ansi(false)
                .with_writer(FfiCallback::new(logger)),
        )
}

struct TelioEventFmt;

impl<S, N> FormatEvent<S, N> for TelioEventFmt
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let tid = std::thread::current().id();
        let meta = event.metadata();
        write!(
            writer,
            "{tid:?} {:?}:{} ",
            meta.module_path().unwrap_or("<unknown module>"),
            meta.line().unwrap_or(0),
        )?;

        ctx.format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

pub struct FfiCallback {
    callback: Arc<dyn TelioLoggerCb>,
}

impl FfiCallback {
    fn new(logger: Box<dyn TelioLoggerCb>) -> Self {
        Self {
            callback: logger.into(),
        }
    }
}

impl<'a> MakeWriter<'a> for FfiCallback {
    type Writer = FfiCallbackWriter;

    fn make_writer(&self) -> Self::Writer {
        unreachable!("`make_writer` should not be called, then `make_writer_for` is implemented")
    }

    fn make_writer_for(&self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        FfiCallbackWriter {
            cb: self.callback.clone(),
            level: (*meta.level()).into(),
        }
    }
}

pub struct FfiCallbackWriter {
    cb: Arc<dyn TelioLoggerCb>,
    level: TelioLogLevel,
}

impl io::Write for FfiCallbackWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // We can be certain that buf fully represents one full event
        //
        // See https://github.com/tokio-rs/tracing/blob/tracing-subscriber-0.3.18/tracing-subscriber/src/fmt/fmt_layer.rs#L975
        //
        // Additional test added to double protect from future breakages

        let msg = from_utf8(buf)
            // Trim could be avoided by removing writeln! in formatter
            // But this makes it more univesal for the future, then we dicide to
            // switch to other formats
            .map(|msg| msg.trim().to_string())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

        if let Some(filtered_msg) = filter_log_message(msg) {
            let filtered_msg = LOG_CENSOR.censor_logs(filtered_msg);

            self.cb
                .log(self.level, filtered_msg)
                .map_err(io::Error::other)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct LogStatus {
    string: String,
    counter: u32,
}

lazy_static::lazy_static! {
    static ref LAST_LOG_STATUS: Mutex<LogStatus> = {
        Mutex::new(LogStatus{string: String::default(), counter: 0})
    };
}

pub static LOG_CENSOR: Lazy<LogCensor> = Lazy::new(LogCensor::default);

fn filter_log_message(msg: String) -> Option<String> {
    let mut log_status = match LAST_LOG_STATUS.lock() {
        Ok(status) => status,
        Err(_) => {
            return None;
        }
    };

    if !log_status.string.eq(&msg) {
        log_status.string = msg.clone();
        log_status.counter = 0;
        return Some(msg);
    }

    if log_status.counter > 0 && log_status.counter % 100 == 0 {
        log_status.counter += 1;
        return Some(format!("[repeated 100 times!] {}", msg));
    }

    if log_status.counter < 10 {
        log_status.counter += 1;
        return Some(msg);
    }

    log_status.counter += 1;
    None
}

#[cfg(test)]
mod test {

    /// Added in external crate to avoid line changes as much as possible
    use tracing::{debug, info, trace, warn};

    use super::*;

    use std::{
        fmt::Debug,
        sync::{Arc, Mutex},
    };

    use crate::{TelioLogLevel, TelioLoggerCb};

    #[test]
    fn test_trace_via_telio_cb() {
        let start = line!() + 1;
        let act = || {
            trace!("first message"); // +1
            debug!("second message"); // +2
            info!("third\nmutiline\nmessage"); // +3
            warn!(
                n = 2,
                extra = "extra info",
                "fourth message with {}",
                "info"
            ); // +4
        };
        let mpath = module_path!();
        let tid = std::thread::current().id();
        let expected = [
            (
                TelioLogLevel::Debug,
                format!("{tid:?} {:?}:{} second message", mpath, start + 2),
            ),
            (
                TelioLogLevel::Info,
                format!("{tid:?} {:?}:{} third\nmutiline\nmessage", mpath, start + 3),
            ),
            (
                TelioLogLevel::Warning,
                format!(
                    "{tid:?} {:?}:{} fourth message with info n=2 extra=\"extra info\"",
                    mpath,
                    start + 4
                ),
            ),
        ];
        let logs = Log::default();
        let subscriber = build_subscriber(TelioLogLevel::Debug, Box::new(logs.clone()));

        tracing::subscriber::with_default(subscriber, act);

        let actual = logs.0.lock().unwrap().clone();

        assert_eq!(&expected[..], &actual[..])
    }

    #[derive(Default, Clone, Debug)]
    struct Log(Arc<Mutex<Vec<(TelioLogLevel, String)>>>);
    impl TelioLoggerCb for Log {
        fn log(&self, level: TelioLogLevel, payload: String) -> crate::FfiResult<()> {
            let mut logs = self.0.lock().expect("Unable to lock");
            logs.push((level, payload));
            Ok(())
        }
    }
}
