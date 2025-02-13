use telio;

mod test_module {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::{sleep, ThreadId},
        time::Duration,
    };

    use telio::{
        ffi_types::{FfiResult, TelioLoggerCb},
        logging::{ASYNC_CHANNEL_CLOSED_MSG, START_ASYNC_LOGGER_MSG},
    };

    use super::*;

    #[ignore]
    #[test]
    fn test_logger() {
        // Line number of tracing::info! call in this fill, down below
        const INFO_LINE1: u32 = 77;
        const INFO_LINE2: u32 = 78;

        let call_count = Arc::new(AtomicUsize::new(0));

        #[derive(Debug)]
        struct TestLogger {
            call_count: Arc<AtomicUsize>,
            log_caller_tid: ThreadId,
        }
        impl TelioLoggerCb for TestLogger {
            fn log(
                &self,
                log_level: telio::ffi_types::TelioLogLevel,
                payload: String,
            ) -> FfiResult<()> {
                sleep(Duration::from_secs(2)); // Slow down logger so that the internal logs queue grows
                println!("{log_level:?} {payload:?}");
                if payload == START_ASYNC_LOGGER_MSG || payload == ASYNC_CHANNEL_CLOSED_MSG {
                    return Ok(());
                }
                let tid = std::thread::current().id();
                assert_ne!(self.log_caller_tid, tid);
                assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));
                if self.call_count.load(Ordering::Relaxed) == 0 {
                    assert_eq!(
                        format!(
                            r#"{:?} "logger::test_module":{INFO_LINE1} test message"#,
                            self.log_caller_tid
                        ),
                        payload
                    );
                } else {
                    assert_eq!(
                        format!(
                            r#"{:?} "logger::test_module":{INFO_LINE2} test message"#,
                            self.log_caller_tid
                        ),
                        payload
                    );
                }
                self.call_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let logger = TestLogger {
            call_count: call_count.clone(),
            log_caller_tid: std::thread::current().id(),
        };

        telio::set_global_logger(telio::ffi_types::TelioLogLevel::Info, Box::new(logger));

        tracing::debug!("this will be ignored since it's below info");
        tracing::info!("test message");
        tracing::info!("test message");

        telio::unset_global_logger();
        assert_eq!(2, call_count.load(Ordering::Relaxed));

        tracing::info!("this will be ignored since it's after the unset_global_logger call");
    }
}
