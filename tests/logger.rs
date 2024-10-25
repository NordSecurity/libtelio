use telio;

mod test_module {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::ThreadId,
    };

    use telio::{
        ffi_types::{FfiResult, TelioLoggerCb},
        logging::START_ASYNC_LOGGER_MSG,
    };

    use super::*;

    #[test]
    fn test_logger() {
        // Line number of tracing::info! location
        const INFO_LINE: u32 = 76;

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
                if payload == START_ASYNC_LOGGER_MSG {
                    return Ok(());
                }
                let tid = std::thread::current().id();

                let call_num = self.call_count.fetch_add(1, Ordering::Relaxed);
                assert!(call_num < 2);

                assert_ne!(self.log_caller_tid, tid);
                assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));

                if call_num == 0 {
                    assert_eq!(
                        format!(
                            r#"{:?} "logger::test_module":{INFO_LINE} test message"#,
                            self.log_caller_tid
                        ),
                        payload
                    );
                }

                if call_num == 1 {
                    assert_eq!(
                        format!(r#"{:?} log crate test message"#, self.log_caller_tid),
                        payload
                    );
                }

                Ok(())
            }
        }

        let logger = Box::new(TestLogger {
            call_count: call_count.clone(),
            log_caller_tid: std::thread::current().id(),
        });

        telio::ffi::set_global_logger(telio::types::TelioLogLevel::Info, logger);

        tracing::info!("test message");

        log::info!("log crate test message");

        while call_count.load(Ordering::Relaxed) < 1 {}

        tracing::debug!("this will be ignored since it's below info");
    }
}
