use crate::telio_log_debug;
use backtrace::{self, BacktraceFrame, BacktraceSymbol};
use findshlibs::{Avma, Segment, SharedLibrary, SharedLibraryId, TargetSharedLibrary};
use parking_lot::Mutex;
use std::path::Path;
use uuid::Uuid;

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

/// Function of a [Backtrace] frame
#[derive(Debug, Clone)]
pub struct Location {
    /// Source file, when debug info is available
    pub file: Option<String>,
    /// Line in the source file, when debug info is available
    pub line: Option<u64>,
    /// Demangled function name, when symbols are available
    pub name: Option<String>,
    /// File name of the binary holding the function
    pub module: Option<String>,
    /// UUID (Apple), GNU build ID (Linux, Android) or PDB GUID and age in symbol server format
    /// (Windows) of the binary
    pub module_id: Option<String>,
    /// Address of the frame in the binary, resolvable offline with the binary's debug file
    pub address: Option<u64>,
}

impl Location {
    fn new(symbol: Option<&BacktraceSymbol>, module: Option<&Module>) -> Self {
        Self {
            file: symbol
                .and_then(|symbol| symbol.filename())
                .map(|file| file.to_string_lossy().into_owned()),
            line: symbol.and_then(|symbol| symbol.lineno()).map(u64::from),
            name: symbol
                .and_then(|symbol| symbol.name())
                .map(|name| name.to_string()),
            module: module.and_then(|module| module.name.clone()),
            module_id: module.and_then(|module| module.id.clone()),
            address: module.map(|module| module.address),
        }
    }
}

struct Module {
    name: Option<String>,
    id: Option<String>,
    address: u64,
}

/// Stack captured when an error is created, symbols are resolved on first use
pub struct Backtrace {
    inner: Mutex<backtrace::Backtrace>,
}

impl Backtrace {
    /// Capture the current stack without resolving symbols
    pub fn capture() -> Self {
        Self {
            inner: Mutex::new(backtrace::Backtrace::new_unresolved()),
        }
    }

    /// Resolve the captured frames into functions, innermost first
    pub fn functions(&self) -> Vec<Location> {
        let mut backtrace = self.inner.lock();
        backtrace.resolve();
        let frames = backtrace.frames();
        frames
            .iter()
            .zip(find_modules(frames))
            .flat_map(|(frame, module)| frame_functions(frame, module.as_ref()))
            .collect()
    }
}

fn frame_functions(frame: &BacktraceFrame, module: Option<&Module>) -> Vec<Location> {
    let symbols = frame.symbols();
    if symbols.is_empty() {
        return vec![Location::new(None, module)];
    }
    symbols
        .iter()
        .map(|symbol| Location::new(Some(symbol), module))
        .collect()
}

fn find_modules(frames: &[BacktraceFrame]) -> Vec<Option<Module>> {
    let mut modules: Vec<Option<Module>> = frames.iter().map(|_| None).collect();
    TargetSharedLibrary::each(|shlib| {
        for (frame, module) in frames.iter().zip(modules.iter_mut()) {
            if module.is_some() {
                continue;
            }
            // Suppose libfoo.so’s symbol table says foo is at 0x1130. That’s
            // an SVMA. At runtime the loader maps the library so the bias is 0x7f3a2c400000,
            // which puts foo at AVMA 0x7f3a2c401130. If your program crashes with an
            // instruction pointer of 0x7f3a2c401145, you subtract the bias to get SVMA 0x1145,
            // look that up in the library’s symbol table or DWARF info, and find that it’s
            // foo+0x15.
            // For details see: https://docs.rs/findshlibs/latest/findshlibs/index.html#addresses
            let ip = Avma(frame.ip() as usize);
            if !shlib
                .segments()
                .any(|segment| segment.contains_avma(shlib, ip))
            {
                continue;
            }
            *module = Some(Module {
                name: Path::new(shlib.name())
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                id: shlib.debug_id().map(format_module_id),
                address: shlib.avma_to_svma(ip).0 as u64,
            });
        }
    });
    modules
}

fn format_module_id(id: SharedLibraryId) -> String {
    match id {
        SharedLibraryId::PdbSignature(guid, age) => {
            format!("{:X}{age:X}", Uuid::from_bytes_le(guid).simple())
        }
        id => id.to_string(),
    }
}

/// Defines `$name` as an error holding `$variant` together with the backtrace of the place where
/// it was created. Anything that converts into `$variant` converts into `$name`, so `?` captures
/// the backtrace.
///
/// Variants wrapping an error that already carries a backtrace are listed in `reuse_backtrace`,
/// so the backtrace of the original error is kept instead of capturing a new one.
///
/// The variant is boxed, so `Result`s carrying the error stay small.
#[macro_export]
macro_rules! traced_error {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident($variant:ident);
        $(reuse_backtrace { $($inner:pat => $traced:expr),* $(,)? })?
    ) => {
        $(#[$attr])*
        $vis struct $name {
            variant: ::std::boxed::Box<$variant>,
            backtrace: ::std::sync::Arc<$crate::backtrace::Backtrace>,
        }

        impl $name {
            /// Kind of the error
            pub fn variant(&self) -> &$variant {
                &self.variant
            }

            /// Backtrace of the place where the error was created
            pub fn backtrace(&self) -> ::std::sync::Arc<$crate::backtrace::Backtrace> {
                self.backtrace.clone()
            }
        }

        impl<E: Into<$variant>> From<E> for $name {
            fn from(variant: E) -> Self {
                let variant = variant.into();
                let backtrace = $crate::traced_error!(@reuse &variant $(, $($inner => $traced),*)?)
                    .unwrap_or_else(|| {
                        ::std::sync::Arc::new($crate::backtrace::Backtrace::capture())
                    });
                Self {
                    variant: ::std::boxed::Box::new(variant),
                    backtrace,
                }
            }
        }

        // Skips the backtrace, so logged errors look the same as the bare variant
        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Debug::fmt(&self.variant, f)
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.variant, f)
            }
        }

        impl ::std::error::Error for $name {
            fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
                ::std::error::Error::source(&self.variant)
            }
        }
    };
    (@reuse $variant:expr) => {
        None
    };
    (@reuse $variant:expr, $($inner:pat => $traced:expr),*) => {
        match $variant {
            $($inner => Some($traced.backtrace()),)*
            _ => None,
        }
    };
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[derive(Debug, thiserror::Error)]
    enum InnerVariant {
        #[error("inner")]
        Inner,
    }

    crate::traced_error! {
        struct InnerError(InnerVariant);
    }

    #[derive(Debug, thiserror::Error)]
    enum OuterVariant {
        #[error(transparent)]
        Inner(#[from] InnerError),
        #[error("outer")]
        Outer,
    }

    crate::traced_error! {
        struct OuterError(OuterVariant);
        reuse_backtrace {
            OuterVariant::Inner(e) => e,
        }
    }

    #[test]
    fn captures_backtrace() {
        let err = OuterError::from(OuterVariant::Outer);
        assert!(matches!(err.variant(), OuterVariant::Outer));
        assert!(!err.backtrace().functions().is_empty());
    }

    #[test]
    fn locates_frames_in_binary() {
        if !findshlibs::TARGET_SUPPORTED {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy();
        let functions = OuterError::from(OuterVariant::Outer)
            .backtrace()
            .functions();
        assert!(functions.iter().any(|function| {
            function.module.as_deref() == Some(&exe)
                && function.module_id.is_some()
                && function.address.is_some()
        }));
    }

    #[test]
    fn formats_pdb_id_as_symbol_server_key() {
        let guid = [
            0x31, 0x4f, 0x5b, 0x74, 0x4b, 0x4d, 0xae, 0x40, 0xa6, 0x05, 0xe4, 0x30, 0xd7, 0x8b,
            0xb7, 0xf3,
        ];
        assert_eq!(
            super::format_module_id(findshlibs::SharedLibraryId::PdbSignature(guid, 0x1a3)),
            "745B4F314D4B40AEA605E430D78BB7F31A3"
        );
    }

    #[test]
    fn reuses_backtrace_of_wrapped_error() {
        let inner = InnerError::from(InnerVariant::Inner);
        assert!(matches!(inner.variant(), InnerVariant::Inner));
        let backtrace = inner.backtrace();
        let outer = OuterError::from(inner);
        assert!(Arc::ptr_eq(&backtrace, &outer.backtrace()));
    }

    #[test]
    fn formats_as_variant() {
        let err = OuterError::from(InnerError::from(InnerVariant::Inner));
        assert_eq!(err.to_string(), "inner");
        assert_eq!(format!("{err:?}"), "Inner(Inner)");
    }
}
