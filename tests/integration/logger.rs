use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use telio::ffi_types::{FfiResult, TelioLoggerCb};

#[test]
fn test_logger() {
    // Line number of tracing::info! location
    const INFO_LINE: u32 = 50;

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
        ) -> FfiResult<()> {
            assert!(matches!(log_level, telio::ffi_types::TelioLogLevel::Info));
            assert_eq!(
                format!(r#""logger::test_module":{INFO_LINE} test message"#),
                payload
            );
            assert_eq!(0, self.call_count.fetch_add(1, Ordering::Relaxed));
            Ok(())
        }
    }

    let logger = TestLogger {
        call_count: call_count.clone(),
    };

    let tracing_subscriber = telio::ffi::logging::build_subscriber(
        telio::ffi_types::TelioLogLevel::Info,
        Box::new(logger),
    );
    tracing::subscriber::set_global_default(tracing_subscriber).unwrap();

    tracing::info!("test message");
    assert_eq!(1, call_count.load(Ordering::Relaxed));
    tracing::debug!("this will be ignored since it's below info");
}
