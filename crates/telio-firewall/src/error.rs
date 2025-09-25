///
/// Possible FW errors
///
#[allow(clippy::enum_variant_names)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwError {
    LibfwSuccess,
    LibfwErrorMalformedIpPacket,
    LibfwErrorMalformedUdpPacket,
    LibfwErrorMalformedTcpPacket,
    LibfwErrorMalformedIcmpPacket,
    LibfwErrorUnexpectedProtocol,
    LibfwErrorInvalidIcmpErrorPayload,
    LibfwErrorUnexpectedPacketType,
    LibfwErrorNullPointer,
    LibfwErrorNotImplemented,
    LibfwErrorInvalidChain,
    //... Expected to be extended during development
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    MalformedIpPacket,
    MalformedUdpPacket,
    MalformedTcpPacket,
    MalformedIcmpPacket,
    UnexpectedProtocol,
    InvalidIcmpErrorPayload,
    UnexpectedPacketType,
    NullPointer,
    NotImplemented,
    InvalidChain,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

impl From<LibfwError> for Result<()> {
    fn from(value: LibfwError) -> Self {
        match value {
            LibfwError::LibfwSuccess => Ok(()),
            LibfwError::LibfwErrorMalformedIpPacket => Err(Error::MalformedIpPacket),
            LibfwError::LibfwErrorMalformedUdpPacket => Err(Error::MalformedUdpPacket),
            LibfwError::LibfwErrorMalformedTcpPacket => Err(Error::MalformedTcpPacket),
            LibfwError::LibfwErrorMalformedIcmpPacket => Err(Error::MalformedIcmpPacket),
            LibfwError::LibfwErrorUnexpectedProtocol => Err(Error::UnexpectedProtocol),
            LibfwError::LibfwErrorInvalidIcmpErrorPayload => Err(Error::InvalidIcmpErrorPayload),
            LibfwError::LibfwErrorUnexpectedPacketType => Err(Error::UnexpectedPacketType),
            LibfwError::LibfwErrorNullPointer => Err(Error::NullPointer),
            LibfwError::LibfwErrorNotImplemented => Err(Error::NotImplemented),
            LibfwError::LibfwErrorInvalidChain => Err(Error::InvalidChain),
        }
    }
}

impl From<Error> for LibfwError {
    fn from(value: Error) -> Self {
        match value {
            Error::MalformedIpPacket => LibfwError::LibfwErrorMalformedIpPacket,
            Error::MalformedUdpPacket => LibfwError::LibfwErrorMalformedUdpPacket,
            Error::MalformedTcpPacket => LibfwError::LibfwErrorMalformedTcpPacket,
            Error::MalformedIcmpPacket => LibfwError::LibfwErrorMalformedIcmpPacket,
            Error::UnexpectedProtocol => LibfwError::LibfwErrorUnexpectedProtocol,
            Error::InvalidIcmpErrorPayload => LibfwError::LibfwErrorInvalidIcmpErrorPayload,
            Error::UnexpectedPacketType => LibfwError::LibfwErrorUnexpectedPacketType,
            Error::NullPointer => LibfwError::LibfwErrorNullPointer,
            Error::NotImplemented => LibfwError::LibfwErrorNotImplemented,
            Error::InvalidChain => LibfwError::LibfwErrorInvalidChain,
        }
    }
}

impl<T> From<Result<T>> for LibfwError {
    fn from(value: Result<T>) -> Self {
        match value {
            Ok(_) => LibfwError::LibfwSuccess,
            Err(err) => err.into(),
        }
    }
}
