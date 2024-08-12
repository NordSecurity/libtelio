use std::{
    io::{self, ErrorKind},
    net::IpAddr,
    str::{from_utf8, FromStr},
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Captures, Regex, RegexBuilder};

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
        let meta = event.metadata();
        write!(
            writer,
            "{:?}:{} ",
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

pub static LOG_CENSOR: Lazy<LogCensor> = Lazy::new(LogCensor::new);

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

#[derive(Debug)]
pub struct LogCensor {
    ip_mask_seed: [u8; 32],
    ip_regex: Regex,
    is_enabled: AtomicBool,
}

#[allow(unused)]
impl LogCensor {
    fn new() -> Self {
        #[allow(clippy::expect_used)]
        RegexBuilder::new(
            r"
                (?:
                    (?:
                        25[0-5]
                        |  2[0-4][0-9]
                        |  1[0-9]{2}
                        |  [1-9]?[0-9]
                    )\.
                ){3}
                (?:
                    25[0-5]
                    |  2[0-4][0-9]
                    |  1[0-9]{2}
                    |  [1-9]?[0-9]
                )
                |
                (?:
                    ([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
                    |   :(:[0-9a-fA-F]{1,4}){1,7}
                    |   ([0-9a-fA-F]{1,4}:){1}(:[0-9a-fA-F]{1,4}){1,6}
                    |   ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}
                    |   ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}
                    |   ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}
                    |   ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}
                    |   ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}
                    |   ([0-9a-fA-F]{1,4}:){1,7}:
                )
                ",
        )
        .ignore_whitespace(true)
        .build()
        .map(|re| LogCensor {
            ip_mask_seed: rand::thread_rng().gen::<[u8; 32]>(),
            ip_regex: re,
            is_enabled: AtomicBool::new(true),
        })
        .expect("Statically known string for LogCensor is a valid regex")
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.is_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    fn should_censor(&self) -> bool {
        self.is_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn censor_logs(&self, log: String) -> String {
        if !self.should_censor() {
            return log;
        }
        // Gather all of the IPs
        let replaced = self.ip_regex.replace_all(&log, |captures: &Captures| {
            captures
                .get(0)
                .map(|ip_match| {
                    let incorret_chars_on_bounds =
                        [ip_match.start().wrapping_sub(1), ip_match.end()]
                            .iter()
                            .flat_map(|pos| log.chars().nth(*pos))
                            .any(|c| c.is_alphanumeric() || c == '_' || c == '.');
                    if incorret_chars_on_bounds {
                        return ip_match.as_str().to_string();
                    }

                    IpAddr::from_str(ip_match.as_str())
                        .map(|ip_addr| {
                            // Probably good enough protection for this usecase
                            let mut hasher = blake3::Hasher::new();
                            match ip_addr {
                                IpAddr::V4(ipv4) => hasher.update(ipv4.octets().as_slice()),
                                IpAddr::V6(ipv6) => hasher.update(ipv6.octets().as_slice()),
                            };
                            hasher.update(&self.ip_mask_seed);

                            // Blake3 hash is much bigger than 8 bytes
                            #[allow(index_access_check)]
                            let hash_prefix = &hasher.finalize().to_hex()[..16];

                            format!("IP({})", hash_prefix)
                        })
                        .unwrap_or(ip_match.as_str().to_owned())
                })
                .unwrap_or(
                    "Regex crate guarantees this, too low priority to panic on its fail, though"
                        .to_string(),
                )
        });

        match replaced {
            std::borrow::Cow::Borrowed(_) => log,
            std::borrow::Cow::Owned(s) => s,
        }
    }
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
        let expected = [
            (
                TelioLogLevel::Debug,
                format!("{:?}:{} second message", mpath, start + 2),
            ),
            (
                TelioLogLevel::Info,
                format!("{:?}:{} third\nmutiline\nmessage", mpath, start + 3),
            ),
            (
                TelioLogLevel::Warning,
                format!(
                    "{:?}:{} fourth message with info n=2 extra=\"extra info\"",
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

    const EXAMPLES: [(&'static str, &'static str); 11] = [
            (
                "1999-09-09 [INFO] New endpoint (1.2.3.4:1234) created",
                "1999-09-09 [INFO] New endpoint (IP(959535cab4852bd4):1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([::aabb]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP(e64601d879a35ebc)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([aabb:1234::]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP(3b50080d1fdc9e80)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoint ([1:2:3:4:5:6:7:8]:1234) created",
                "1999-09-09 [INFO] New endpoint ([IP(6673d2027ae3aae5)]:1234) created",
            ),
            (
                "1999-09-09 [INFO] New endpoints: [1:2::8]:1234 and 4.3.2.1:1234 created",
                "1999-09-09 [INFO] New endpoints: [IP(dd87bb66675bdace)]:1234 and IP(89e69e5aeec9ec9b):1234 created",
            ),
            (
                "1999-09-09 [INFO] \"telio::device::wg_controller\":295 peer \"YOla...oFc=\" proxying: true, state: Connected, last handshake: Some(1719486326.132445116s)",
                "1999-09-09 [INFO] \"telio::device::wg_controller\":295 peer \"YOla...oFc=\" proxying: true, state: Connected, last handshake: Some(1719486326.132445116s)",
            ),
            (
                "255.255.255.255 IPv4 at the beginning and at the end 0.0.0.0",
                "IP(8be193f535e5b88f) IPv4 at the beginning and at the end IP(245097bfbd7049db)",
            ),
            (
                "255.255.255.255aa we don't count these as IPv4s 0.0.0.0_a",
                "255.255.255.255aa we don't count these as IPv4s 0.0.0.0_a",
            ),
            (
                "::cd IPv6 at the beginning and at the end a:b::c:d",
                "IP(c3d82cb949013623) IPv6 at the beginning and at the end IP(0525ccdac7d4904a)",
            ),
            (
                "mace::cdcd no IPv6 addresses here crypto_aead::aead",
                "mace::cdcd no IPv6 addresses here crypto_aead::aead",
            ),
            (
                "A list of IPv6, IPv4 and some strange mix: [a:b:c::d:e:f, 1.2.3.4, 1.2::c:d]",
                "A list of IPv6, IPv4 and some strange mix: [IP(46ba26199a45b3a1), IP(959535cab4852bd4), 1.2::c:d]",
            ),
        ];

    #[test]
    fn test_log_censor() {
        let mut censor = LogCensor::new();

        // For the tests we need it repeatable and seed filled with zeros is good as any other
        censor.ip_mask_seed = [0; 32];

        for (original_log, expected_censored_log) in EXAMPLES {
            assert_eq!(
                expected_censored_log,
                censor.censor_logs(original_log.to_owned())
            );
        }
    }

    #[test]
    fn test_log_censor_makes_no_copies_when_not_needed() {
        let censor = LogCensor::new();

        let input = "this is some text that is going to be censored by the censor by it shouldn't match anything in the regex".to_owned();
        let input_copy = input.clone();
        let input_ptr = input.as_str().as_ptr();
        let censored = censor.censor_logs(input);
        assert_eq!(input_copy, censored);

        // No copies are made when the string doesn't need any modifications
        let censored_ptr = censored.as_str().as_ptr();
        assert_eq!(input_ptr, censored_ptr);
    }

    #[test]
    fn test_disabled_log_censor_makes_no_modifications() {
        let censor = LogCensor::new();
        censor.set_enabled(false);
        for (original_log, _) in EXAMPLES {
            let original_log_copy = original_log.to_owned();
            let original_log_ptr = original_log_copy.as_str().as_ptr();
            let new_log = censor.censor_logs(original_log_copy);
            assert_eq!(original_log, new_log);
            // No copies are made when the string doesn't need any modifications
            let new_log_ptr = new_log.as_str().as_ptr();
            assert_eq!(original_log_ptr, new_log_ptr);
        }
    }
}
