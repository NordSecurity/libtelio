use log::{Level, RecordBuilder};
use std::fmt::Debug;
use tracing::{
    event::Event,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    Metadata, Subscriber,
};

/// Visitor for `tracing` events that converts one field with name equal to `field_name`
/// value to a `log::Record`.
pub struct NamedFieldLogger<'a, 'b> {
    field_name: &'static str,
    metadata: &'a Metadata<'b>,
    level: Level,
}

impl<'a, 'b> Visit for NamedFieldLogger<'a, 'b> {
    #[track_caller]
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == self.field_name {
            log::logger().log(
                &RecordBuilder::new()
                    .args(format_args!("{:?}", value))
                    .level(self.level)
                    .target(self.metadata.target())
                    .file(self.metadata.file())
                    .line(self.metadata.line())
                    .module_path(self.metadata.module_path())
                    .build(),
            );
        }
        // Do nothing, for now only handle one field
    }
}

/// Subscriber for `tracing` that will convert adhoc events created via macros like `tracing::info!`
/// to logs created via `log` crate.
pub struct TracingToLogConverter;

impl Subscriber for TracingToLogConverter {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &tracing::level_filters::STATIC_MAX_LEVEL
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        // It seems that for now it doesn't matter in our case so to make it as simple
        // and cheap as possible we return hardcoded value that is not present in the
        // codebase (so that if we spot it somewhere it's easier to track it down to this place)
        Id::from_u64(1337)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {
        // Explicitly not implemented since it's seems not needed for tracing::info! kind of usage we want to handle
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {
        // Explicitly not implemented since it's seems not needed for tracing::info! kind of usage we want to handle
    }

    fn event(&self, event: &Event<'_>) {
        // Can't match since tracing::Level is opaque type...
        let level = if event.metadata().level() == &tracing::Level::TRACE {
            Level::Trace
        } else if event.metadata().level() == &tracing::Level::DEBUG {
            Level::Debug
        } else if event.metadata().level() == &tracing::Level::WARN {
            Level::Warn
        } else if event.metadata().level() == &tracing::Level::ERROR {
            Level::Error
        } else if event.metadata().level() == &tracing::Level::INFO {
            Level::Info
        } else {
            // Should never happen, defaulting to error to make it easier to detect if it happens
            Level::Error
        };
        let mut visitor = NamedFieldLogger {
            // hardcoded name of the field where tracing stores the messages passed to tracing::info! etc
            field_name: "message",
            metadata: event.metadata(),
            level,
        };
        event.record(&mut visitor);
    }

    fn enter(&self, _span: &Id) {
        // Explicitly not implemented since it's seems not needed for tracing::info! kind of usage we want to handle
    }

    fn exit(&self, _span: &Id) {
        // Explicitly not implemented since it's seems not needed for tracing::info! kind of usage we want to handle
    }
}
