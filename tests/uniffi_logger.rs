use telio;
use telio::TelioTracingSubscriber;

mod test_module {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use telio::{ffi_types::TelioLoggerCb, SubscriberCallback};

    use super::*;

    #[test]
    fn uniffi_test_logger() {
        let call_count = Arc::new(AtomicUsize::new(0));

        #[derive(Debug)]
        struct TestLogger {
            call_count: Arc<AtomicUsize>,
        }
        impl TelioLoggerCb for TestLogger {
            fn log(&self, log_level: telio::ffi_types::TelioLogLevel, payload: String) {
                assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));
                assert_eq!(r#""uniffi_logger::test_module":40 test message"#, payload);
                assert_eq!(0, self.call_count.fetch_add(1, Ordering::Relaxed));
            }
        }

        let logger = TestLogger {
            call_count: call_count.clone(),
        };

        let tracing_subscriber = TelioTracingSubscriber::new(
            SubscriberCallback::Uniffi(Box::new(logger)),
            tracing::Level::INFO,
        );
        tracing::subscriber::set_global_default(tracing_subscriber).unwrap();

        tracing::info!("test message");
        assert_eq!(1, call_count.load(Ordering::Relaxed));
        tracing::debug!("this will be ignored since it's below info");
    }
}