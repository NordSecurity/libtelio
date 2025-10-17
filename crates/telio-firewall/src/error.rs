///
/// Possible FW errors
///
#[allow(clippy::enum_variant_names)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwResult {
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

impl From<LibfwResult> for Result<()> {
    fn from(value: LibfwResult) -> Self {
        match value {
            LibfwResult::LibfwSuccess => Ok(()),
            LibfwResult::LibfwErrorMalformedIpPacket => Err(Error::MalformedIpPacket),
            LibfwResult::LibfwErrorMalformedUdpPacket => Err(Error::MalformedUdpPacket),
            LibfwResult::LibfwErrorMalformedTcpPacket => Err(Error::MalformedTcpPacket),
            LibfwResult::LibfwErrorMalformedIcmpPacket => Err(Error::MalformedIcmpPacket),
            LibfwResult::LibfwErrorUnexpectedProtocol => Err(Error::UnexpectedProtocol),
            LibfwResult::LibfwErrorInvalidIcmpErrorPayload => Err(Error::InvalidIcmpErrorPayload),
            LibfwResult::LibfwErrorUnexpectedPacketType => Err(Error::UnexpectedPacketType),
            LibfwResult::LibfwErrorNullPointer => Err(Error::NullPointer),
            LibfwResult::LibfwErrorNotImplemented => Err(Error::NotImplemented),
            LibfwResult::LibfwErrorInvalidChain => Err(Error::InvalidChain),
        }
    }
}

impl From<Error> for LibfwResult {
    fn from(value: Error) -> Self {
        match value {
            Error::MalformedIpPacket => LibfwResult::LibfwErrorMalformedIpPacket,
            Error::MalformedUdpPacket => LibfwResult::LibfwErrorMalformedUdpPacket,
            Error::MalformedTcpPacket => LibfwResult::LibfwErrorMalformedTcpPacket,
            Error::MalformedIcmpPacket => LibfwResult::LibfwErrorMalformedIcmpPacket,
            Error::UnexpectedProtocol => LibfwResult::LibfwErrorUnexpectedProtocol,
            Error::InvalidIcmpErrorPayload => LibfwResult::LibfwErrorInvalidIcmpErrorPayload,
            Error::UnexpectedPacketType => LibfwResult::LibfwErrorUnexpectedPacketType,
            Error::NullPointer => LibfwResult::LibfwErrorNullPointer,
            Error::NotImplemented => LibfwResult::LibfwErrorNotImplemented,
            Error::InvalidChain => LibfwResult::LibfwErrorInvalidChain,
        }
    }
}

impl<T> From<Result<T>> for LibfwResult {
    fn from(value: Result<T>) -> Self {
        match value {
            Ok(_) => LibfwResult::LibfwSuccess,
            Err(err) => err.into(),
        }
    }
}
