use telio;
use telio::TelioTracingSubscriber;

mod test_module {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use telio::ffi_types::{FFIResult, TelioLoggerCb};

    use super::*;

    #[test]
    fn test_logger() {
        let call_count = Arc::new(AtomicUsize::new(0));

        #[derive(Debug)]
        struct TestLogger {
            call_count: Arc<AtomicUsize>,
        }
        impl TelioLoggerCb for TestLogger {
            fn log(
                &self,
                log_level: telio::ffi_types::TelioLogLevel,
                payload: String,
            ) -> FFIResult<()> {
                assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));
                assert_eq!(r#""logger::test_module":43 test message"#, payload);
                assert_eq!(0, self.call_count.fetch_add(1, Ordering::Relaxed));
                Ok(())
            }
        }

        let logger = TestLogger {
            call_count: call_count.clone(),
        };

        let tracing_subscriber =
            TelioTracingSubscriber::new(Box::new(logger), tracing::Level::INFO);
        tracing::subscriber::set_global_default(tracing_subscriber).unwrap();

        tracing::info!("test message");
        assert_eq!(1, call_count.load(Ordering::Relaxed));
        tracing::debug!("this will be ignored since it's below info");
    }
}
