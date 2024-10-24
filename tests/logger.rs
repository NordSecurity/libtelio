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
        const INFO_LINE: u32 = 66;

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
                assert_ne!(self.log_caller_tid, tid);
                assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));
                assert_eq!(
                    format!(
                        r#"{:?} "logger::test_module":{INFO_LINE} test message"#,
                        self.log_caller_tid
                    ),
                    payload
                );
                assert_eq!(0, self.call_count.fetch_add(1, Ordering::Relaxed));
                Ok(())
            }
        }

        let logger = TestLogger {
            call_count: call_count.clone(),
            log_caller_tid: std::thread::current().id(),
        };

        let tracing_subscriber = telio::ffi::logging::build_subscriber(
            telio::ffi_types::TelioLogLevel::Info,
            Box::new(logger),
        );
        tracing::subscriber::set_global_default(tracing_subscriber).unwrap();

        tracing::info!("test message");
        while call_count.load(Ordering::Relaxed) < 1 {}
        tracing::debug!("this will be ignored since it's below info");
    }
}
