//! Error types for libfirewall

use std::io::{self, Error, ErrorKind};

///
/// Possible FW errors
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwError {
    /// Function exectuted successfully
    LibfwSuccess,
    /// Given chain is malformed
    LibfwErrorInvalidChain,
    /// Function is not implemented yet
    LibfwErrorNotImplemented,
    /// Unexpected NULL pointer provieded to API
    LibfwErrorNullPointer,

    //
    // Errors equivalent to io::ErrorKind values
    //
    /// Equivalent of ErrorKind::NotFound
    LibfwErrorNotFound,
    /// Equivalent of ErrorKind::PermissionDenied
    LibfwErrorPermissionDenied,
    /// Equivalent of ErrorKind::ConnectionRefused
    LibfwErrorConnectionRefused,
    /// Equivalent of ErrorKind::ConnectionReset
    LibfwErrorConnectionReset,
    /// Equivalent of ErrorKind::HostUnreachable
    LibfwErrorHostUnreachable,
    /// Equivalent of ErrorKind::NetworkUnreachable
    LibfwErrorNetworkUnreachable,
    /// Equivalent of ErrorKind::ConnectionAborted
    LibfwErrorConnectionAborted,
    /// Equivalent of ErrorKind::NotConnected
    LibfwErrorNotConnected,
    /// Equivalent of ErrorKind::AddrInUse
    LibfwErrorAddrInUse,
    /// Equivalent of ErrorKind::AddrNotAvailable
    LibfwErrorAddrNotAvailable,
    /// Equivalent of ErrorKind::NetworkDown
    LibfwErrorNetworkDown,
    /// Equivalent of ErrorKind::BrokenPipe
    LibfwErrorBrokenPipe,
    /// Equivalent of ErrorKind::AlreadyExists
    LibfwErrorAlreadyExists,
    /// Equivalent of ErrorKind::WouldBlock
    LibfwErrorWouldBlock,
    /// Equivalent of ErrorKind::NotADirectory
    LibfwErrorNotADirectory,
    /// Equivalent of ErrorKind::IsADirectory
    LibfwErrorIsADirectory,
    /// Equivalent of ErrorKind::DirectoryNotEmpty
    LibfwErrorDirectoryNotEmpty,
    /// Equivalent of ErrorKind::ReadOnlyFilesystem
    LibfwErrorReadOnlyFilesystem,
    /// Equivalent of ErrorKind::FilesystemLoop
    LibfwErrorFilesystemLoop,
    /// Equivalent of ErrorKind::StaleNetworkFileHandle
    LibfwErrorStaleNetworkFileHandle,
    /// Equivalent of ErrorKind::InvalidInput
    LibfwErrorInvalidInput,
    /// Equivalent of ErrorKind::InvalidData
    LibfwErrorInvalidData,
    /// Equivalent of ErrorKind::TimedOut
    LibfwErrorTimedOut,
    /// Equivalent of ErrorKind::WriteZero
    LibfwErrorWriteZero,
    /// Equivalent of ErrorKind::StorageFull
    LibfwErrorStorageFull,
    /// Equivalent of ErrorKind::NotSeekable
    LibfwErrorNotSeekable,
    /// Equivalent of ErrorKind::QuotaExceeded
    LibfwErrorQuotaExceeded,
    /// Equivalent of ErrorKind::FileTooLarge
    LibfwErrorFileTooLarge,
    /// Equivalent of ErrorKind::ResourceBusy
    LibfwErrorResourceBusy,
    /// Equivalent of ErrorKind::ExecutableFileBusy
    LibfwErrorExecutableFileBusy,
    /// Equivalent of ErrorKind::Deadlock
    LibfwErrorDeadlock,
    /// Equivalent of ErrorKind::CrossesDevices
    LibfwErrorCrossesDevices,
    /// Equivalent of ErrorKind::TooManyLinks
    LibfwErrorTooManyLinks,
    /// Equivalent of ErrorKind::InvalidFilename
    LibfwErrorInvalidFilename,
    /// Equivalent of ErrorKind::ArgumentListTooLong
    LibfwErrorArgumentListTooLong,
    /// Equivalent of ErrorKind::Interrupted
    LibfwErrorInterrupted,
    /// Equivalent of ErrorKind::Unsupported
    LibfwErrorUnsupported,
    /// Equivalent of ErrorKind::UnexpectedEof
    LibfwErrorUnexpectedEof,
    /// Equivalent of ErrorKind::OutOfMemory
    LibfwErrorOutOfMemory,
    /// Equivalent of ErrorKind::InProgress
    LibfwErrorInProgress,
    /// Equivalent of ErrorKind::Other
    LibfwErrorOther,
}

impl From<io::Result<()>> for LibfwError {
    fn from(value: io::Result<()>) -> Self {
        match value {
            Ok(_) => LibfwError::LibfwSuccess,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => LibfwError::LibfwErrorNotFound,
                ErrorKind::PermissionDenied => LibfwError::LibfwErrorPermissionDenied,
                ErrorKind::ConnectionRefused => LibfwError::LibfwErrorConnectionRefused,
                ErrorKind::ConnectionReset => LibfwError::LibfwErrorConnectionReset,
                ErrorKind::HostUnreachable => LibfwError::LibfwErrorHostUnreachable,
                ErrorKind::NetworkUnreachable => LibfwError::LibfwErrorNetworkUnreachable,
                ErrorKind::ConnectionAborted => LibfwError::LibfwErrorConnectionAborted,
                ErrorKind::NotConnected => LibfwError::LibfwErrorNotConnected,
                ErrorKind::AddrInUse => LibfwError::LibfwErrorAddrInUse,
                ErrorKind::AddrNotAvailable => LibfwError::LibfwErrorAddrNotAvailable,
                ErrorKind::NetworkDown => LibfwError::LibfwErrorNetworkDown,
                ErrorKind::BrokenPipe => LibfwError::LibfwErrorBrokenPipe,
                ErrorKind::AlreadyExists => LibfwError::LibfwErrorAlreadyExists,
                ErrorKind::WouldBlock => LibfwError::LibfwErrorWouldBlock,
                ErrorKind::NotADirectory => LibfwError::LibfwErrorNotADirectory,
                ErrorKind::IsADirectory => LibfwError::LibfwErrorIsADirectory,
                ErrorKind::DirectoryNotEmpty => LibfwError::LibfwErrorDirectoryNotEmpty,
                ErrorKind::ReadOnlyFilesystem => LibfwError::LibfwErrorReadOnlyFilesystem,
                ErrorKind::StaleNetworkFileHandle => LibfwError::LibfwErrorStaleNetworkFileHandle,
                ErrorKind::InvalidInput => LibfwError::LibfwErrorInvalidInput,
                ErrorKind::InvalidData => LibfwError::LibfwErrorInvalidData,
                ErrorKind::TimedOut => LibfwError::LibfwErrorTimedOut,
                ErrorKind::WriteZero => LibfwError::LibfwErrorWriteZero,
                ErrorKind::StorageFull => LibfwError::LibfwErrorStorageFull,
                ErrorKind::NotSeekable => LibfwError::LibfwErrorNotSeekable,
                ErrorKind::QuotaExceeded => LibfwError::LibfwErrorQuotaExceeded,
                ErrorKind::FileTooLarge => LibfwError::LibfwErrorFileTooLarge,
                ErrorKind::ResourceBusy => LibfwError::LibfwErrorResourceBusy,
                ErrorKind::ExecutableFileBusy => LibfwError::LibfwErrorExecutableFileBusy,
                ErrorKind::Deadlock => LibfwError::LibfwErrorDeadlock,
                ErrorKind::CrossesDevices => LibfwError::LibfwErrorCrossesDevices,
                ErrorKind::TooManyLinks => LibfwError::LibfwErrorTooManyLinks,
                ErrorKind::ArgumentListTooLong => LibfwError::LibfwErrorArgumentListTooLong,
                ErrorKind::Interrupted => LibfwError::LibfwErrorInterrupted,
                ErrorKind::Unsupported => LibfwError::LibfwErrorUnsupported,
                ErrorKind::UnexpectedEof => LibfwError::LibfwErrorUnexpectedEof,
                ErrorKind::OutOfMemory => LibfwError::LibfwErrorOutOfMemory,
                ErrorKind::Other => LibfwError::LibfwErrorOther,
                _ => LibfwError::LibfwErrorOther,
            },
        }
    }
}

impl From<LibfwError> for io::Result<()> {
    fn from(value: LibfwError) -> Self {
        match value {
            LibfwError::LibfwSuccess => Ok(()),
            err => {
                let io_error_kind = match err {
                    LibfwError::LibfwErrorNotFound => ErrorKind::NotFound,
                    LibfwError::LibfwErrorPermissionDenied => ErrorKind::PermissionDenied,
                    LibfwError::LibfwErrorConnectionRefused => ErrorKind::ConnectionRefused,
                    LibfwError::LibfwErrorConnectionReset => ErrorKind::ConnectionReset,
                    LibfwError::LibfwErrorHostUnreachable => ErrorKind::HostUnreachable,
                    LibfwError::LibfwErrorNetworkUnreachable => ErrorKind::NetworkUnreachable,
                    LibfwError::LibfwErrorConnectionAborted => ErrorKind::ConnectionAborted,
                    LibfwError::LibfwErrorNotConnected => ErrorKind::NotConnected,
                    LibfwError::LibfwErrorAddrInUse => ErrorKind::AddrInUse,
                    LibfwError::LibfwErrorAddrNotAvailable => ErrorKind::AddrNotAvailable,
                    LibfwError::LibfwErrorNetworkDown => ErrorKind::NetworkDown,
                    LibfwError::LibfwErrorBrokenPipe => ErrorKind::BrokenPipe,
                    LibfwError::LibfwErrorAlreadyExists => ErrorKind::AlreadyExists,
                    LibfwError::LibfwErrorWouldBlock => ErrorKind::WouldBlock,
                    LibfwError::LibfwErrorNotADirectory => ErrorKind::NotADirectory,
                    LibfwError::LibfwErrorIsADirectory => ErrorKind::IsADirectory,
                    LibfwError::LibfwErrorDirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
                    LibfwError::LibfwErrorReadOnlyFilesystem => ErrorKind::ReadOnlyFilesystem,
                    LibfwError::LibfwErrorStaleNetworkFileHandle => {
                        ErrorKind::StaleNetworkFileHandle
                    }
                    LibfwError::LibfwErrorInvalidInput => ErrorKind::InvalidInput,
                    LibfwError::LibfwErrorInvalidData => ErrorKind::InvalidData,
                    LibfwError::LibfwErrorTimedOut => ErrorKind::TimedOut,
                    LibfwError::LibfwErrorWriteZero => ErrorKind::WriteZero,
                    LibfwError::LibfwErrorStorageFull => ErrorKind::StorageFull,
                    LibfwError::LibfwErrorNotSeekable => ErrorKind::NotSeekable,
                    LibfwError::LibfwErrorQuotaExceeded => ErrorKind::QuotaExceeded,
                    LibfwError::LibfwErrorFileTooLarge => ErrorKind::FileTooLarge,
                    LibfwError::LibfwErrorResourceBusy => ErrorKind::ResourceBusy,
                    LibfwError::LibfwErrorExecutableFileBusy => ErrorKind::ExecutableFileBusy,
                    LibfwError::LibfwErrorDeadlock => ErrorKind::Deadlock,
                    LibfwError::LibfwErrorCrossesDevices => ErrorKind::CrossesDevices,
                    LibfwError::LibfwErrorTooManyLinks => ErrorKind::TooManyLinks,
                    LibfwError::LibfwErrorArgumentListTooLong => ErrorKind::ArgumentListTooLong,
                    LibfwError::LibfwErrorInterrupted => ErrorKind::Interrupted,
                    LibfwError::LibfwErrorUnsupported => ErrorKind::Unsupported,
                    LibfwError::LibfwErrorUnexpectedEof => ErrorKind::UnexpectedEof,
                    LibfwError::LibfwErrorOutOfMemory => ErrorKind::OutOfMemory,
                    LibfwError::LibfwErrorOther => ErrorKind::Other,
                    _ => ErrorKind::Other,
                };
                Err(Error::from(io_error_kind))
            }
        }
    }
}
