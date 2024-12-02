use crate::telio_log_debug;
use backtrace;

/// Print to debug log current backtrace
pub fn log_current_backtrace() {
    let mut counter = 0;
    backtrace::trace(|frame| {
        let ip = frame.ip();
        let symbol_address = frame.symbol_address();

        // Resolve this instruction pointer to a symbol name
        backtrace::resolve_frame(frame, |symbol| {
            let name = symbol
                .name()
                .map(|symbol| symbol.to_string())
                .unwrap_or_else(|| format!("{symbol_address:?}"));

            let filename = symbol
                .filename()
                .map(|filename| filename.to_string_lossy().into_owned())
                .unwrap_or_else(|| "uknown.file".to_owned());

            let lineno = symbol.lineno().unwrap_or(0);

            telio_log_debug!("backtrace: {counter:3} {ip:?} {filename}:{lineno} {name}");
            counter += 1;
        });

        true
    });
}
