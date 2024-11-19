use std::{
    io::{self, ErrorKind},
    str::from_utf8,
    sync::{
        atomic::AtomicUsize,
        mpsc::{sync_channel, RecvError, SyncSender},
        Arc, Barrier, Mutex,
    },
    thread::Builder,
    time::Instant,
};

use once_cell::sync::Lazy;
use telio_utils::log_censor::LogCensor;
use tracing::{level_filters::LevelFilter, Subscriber};
use tracing_subscriber::{
    fmt::{self, FormatEvent, FormatFields, MakeWriter},
    layer::SubscriberExt,
    registry::LookupSpan,
};

use crate::{TelioLogLevel, TelioLoggerCb};

const LOG_BUFFER: usize = 1024;
pub const START_ASYNC_LOGGER_MSG: &str = "Starting async logger thread";
pub const ASYNC_CHANNEL_CLOSED_MSG: &str = "Async channel explicitly closed";

static DROPPED_LOGS: AtomicUsize = AtomicUsize::new(0);
static DROPPED_LOGS_LAST_CHECKED_VALUE: AtomicUsize = AtomicUsize::new(0);
pub static LOGGER_STOPPER: LoggerStopper = LoggerStopper::new();

pub struct LoggerStopper {
    sender: parking_lot::Mutex<Option<SyncSender<LogMessage>>>,
}

impl LoggerStopper {
    const fn new() -> Self {
        Self {
            sender: parking_lot::Mutex::new(None),
        }
    }

    fn set_sender(&self, sender: SyncSender<LogMessage>) {
        *self.sender.lock() = Some(sender);
    }

    pub fn stop(&self) {
        match *self.sender.lock() {
            Some(ref sender) => {
                stop_logger_thread(sender, true);
            }
            None => {
                println!("No global logger set");
            }
        }
    }
}

fn stop_logger_thread(sender: &SyncSender<LogMessage>, explicit: bool) {
    let kind = if explicit { "explicit " } else { "" };
    let start = Instant::now();
    let b = Arc::new(Barrier::new(2));
    match sender.try_send(LogMessage::Quit(b.clone())) {
        Ok(()) => {
            b.wait();
            println!("Waited for {kind}log flush for {:?}", start.elapsed());
        }
        Err(e) => {
            eprintln!("Failed to do {kind}log flush: {e}");
        }
    }
}

/// Return the total number of log messages droppped since the process has started
pub fn logs_dropped_until_now() -> usize {
    DROPPED_LOGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Return the number of log messages dropped since the last time this function was called
pub fn logs_dropped_since_last_checked() -> usize {
    let current = DROPPED_LOGS.load(std::sync::atomic::Ordering::Relaxed);
    let last = DROPPED_LOGS_LAST_CHECKED_VALUE.swap(current, std::sync::atomic::Ordering::Relaxed);
    current - last
}

/// Build a tracing subscriber for use in ffi
pub fn build_subscriber(
    log_level: crate::TelioLogLevel,
    logger: Box<dyn TelioLoggerCb>,
) -> impl Subscriber {
    let log_sender = start_async_logger(logger, LOG_BUFFER);
    LOGGER_STOPPER.set_sender(log_sender.clone());
    tracing_subscriber::registry()
        .with(LevelFilter::from_level(log_level.into()))
        .with(
            fmt::layer()
                .event_format(TelioEventFmt)
                .with_ansi(false)
                .with_writer(FfiCallback::new(log_sender)),
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
    log_sender: SyncSender<LogMessage>,
}

impl FfiCallback {
    fn new(log_sender: SyncSender<LogMessage>) -> Self {
        Self { log_sender }
    }
}

#[cfg(test)]
impl Drop for FfiCallback {
    fn drop(&mut self) {
        stop_logger_thread(&self.log_sender, false)
    }
}

impl<'a> MakeWriter<'a> for FfiCallback {
    type Writer = FfiCallbackWriter;

    fn make_writer(&self) -> Self::Writer {
        unreachable!("`make_writer` should not be called, then `make_writer_for` is implemented")
    }

    fn make_writer_for(&self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        FfiCallbackWriter {
            log_sender: self.log_sender.clone(),
            level: (*meta.level()).into(),
        }
    }
}

pub struct FfiCallbackWriter {
    log_sender: SyncSender<LogMessage>,
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

            // There are only 2 reasons why try_send should fail:
            // - no more space in a buffer because we are not processing logs fast enough
            // - the receiving thread has already stopped
            // In both cases there is nothing to do when it happens.
            if self
                .log_sender
                .try_send(LogMessage::Message(self.level, filtered_msg))
                .is_err()
            {
                DROPPED_LOGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
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

enum LogMessage {
    Message(TelioLogLevel, String),
    Quit(Arc<Barrier>),
}

fn start_async_logger(cb: Box<dyn TelioLoggerCb>, buffer_size: usize) -> SyncSender<LogMessage> {
    let (sender, receiver) = sync_channel::<LogMessage>(buffer_size);
    let handle = Builder::new()
        .name("libtelio-logger".to_owned())
        .spawn(move || {
            let _ = cb.log(TelioLogLevel::Debug, START_ASYNC_LOGGER_MSG.to_owned());
            loop {
                match receiver.recv() {
                    Ok(LogMessage::Message(level, msg)) => {
                        let _ = cb.log(level, msg);
                    }
                    Ok(LogMessage::Quit(barrier)) => {
                        let _ = cb.log(TelioLogLevel::Debug, ASYNC_CHANNEL_CLOSED_MSG.to_owned());
                        barrier.wait();
                        break;
                    }
                    Err(RecvError) => {
                        let _ = cb.log(
                            TelioLogLevel::Debug,
                            "Async channel implicitly closed".to_owned(),
                        );
                        break;
                    }
                }
            }
            println!("Global logging thread ending");
        });
    if let Err(e) = handle {
        eprintln!("Failed to start logging thread: {e:?}");
    }
    sender
}

#[cfg(test)]
mod test {

    /// Added in external crate to avoid line changes as much as possible
    use tracing::{debug, info, trace, warn};

    use super::*;

    use std::{
        fmt::Debug,
        sync::{Arc, Mutex},
        thread::sleep,
        time::Duration,
    };

    use crate::{TelioLogLevel, TelioLoggerCb};

    #[test]
    fn test_trace_via_telio_cb() {
        const EXPECTED_SIZE: usize = 5;

        let log = Log::default();
        let logs = log.0.clone();

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
        let expected: [_; EXPECTED_SIZE] = [
            (TelioLogLevel::Debug, START_ASYNC_LOGGER_MSG.to_owned()),
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
            (TelioLogLevel::Debug, ASYNC_CHANNEL_CLOSED_MSG.to_owned()),
        ];

        let subscriber = build_subscriber(TelioLogLevel::Debug, Box::new(log));

        tracing::subscriber::with_default(subscriber, act);

        // Need to wait for the async thread to process above logs
        while logs.lock().unwrap().len() < EXPECTED_SIZE {
            println!("collected logs count: {}", logs.lock().unwrap().len());
        }
        let actual = logs.lock().unwrap().clone();
        assert_eq!(&expected[..], &actual[..]);
    }

    #[test]
    fn test_trace_via_slow_telio_cb() {
        const EXPECTED_SIZE: usize = 5;

        let log = SlowLog::default();
        let logs = log.0.clone();

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
        let expected: [_; EXPECTED_SIZE] = [
            (TelioLogLevel::Debug, START_ASYNC_LOGGER_MSG.to_owned()),
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
            (TelioLogLevel::Debug, ASYNC_CHANNEL_CLOSED_MSG.to_owned()),
        ];

        let subscriber = build_subscriber(TelioLogLevel::Debug, Box::new(log));

        tracing::subscriber::with_default(subscriber, act);

        let actual = logs.lock().unwrap().clone();
        assert_eq!(&expected[..], &actual[..]);
    }

    #[test]
    fn blocking_telio_cb_handling() {
        const LOGS_TO_DROP: usize = 5;
        let log = BlockedLog::default();
        let subscriber = build_subscriber(TelioLogLevel::Debug, Box::new(log));

        tracing::subscriber::with_default(subscriber, || {
            for i in 0..(LOG_BUFFER + LOGS_TO_DROP) {
                info!("Test log with some changing data: {i}");
            }
            assert_eq!(LOGS_TO_DROP, logs_dropped_since_last_checked());

            info!("Another unique log message");

            assert_eq!(1, logs_dropped_since_last_checked());
        });

        assert_eq!(LOGS_TO_DROP + 1, logs_dropped_until_now());
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

    #[derive(Default, Clone, Debug)]
    struct SlowLog(Arc<Mutex<Vec<(TelioLogLevel, String)>>>);
    impl TelioLoggerCb for SlowLog {
        fn log(&self, level: TelioLogLevel, payload: String) -> crate::FfiResult<()> {
            sleep(Duration::from_secs(1));
            let mut logs = self.0.lock().expect("Unable to lock");
            logs.push((level, payload));
            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct BlockedLog;
    impl TelioLoggerCb for BlockedLog {
        fn log(&self, _level: TelioLogLevel, _payload: String) -> crate::FfiResult<()> {
            loop {}
        }
    }
}
