use bytes::BufMut;
use std::{
    convert::{TryFrom, TryInto},
    net::{IpAddr, Ipv4Addr},
};
use telio_crypto::PublicKey;
use telio_model::api_config::EndpointProvider;

use crate::{
    messages::pinger::*, Codec, CodecError, CodecResult, DowncastPacket, PacketRelayed,
    PacketTypeRelayed, Session, WGPort, MAX_PACKET_SIZE,
};
use protobuf::Message;

/// Unix timestamp in milliseconds
pub type Timestamp = u64;

/// Packet encapsulating containing WG packets
/// # Examples
/// Decoding ping message:
/// ```rust
/// # use crate::telio_proto::{Codec, PingerMsg, PacketTypeRelayed};
/// let bytes = &[7, 0, 0, 0, 0, 0, 0, 0, 9, 8, 128, 2, 16, 8];
/// let data = PingerMsg::decode(bytes).expect("Failed to parse packet");
/// assert_eq!(data.packet_type(), PacketTypeRelayed::Pinger);
/// assert_eq!(data.get_wg_port().0, 8_u16);
/// assert_eq!(data.get_session(), 9_u64);
/// assert_eq!(data.get_start_timestamp(), 256_u64);
///
/// assert_eq!(bytes, data.encode().unwrap().as_slice());
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct PingerMsg {
    session: Session,
    msg: Pinger,
}

/// Reply to `PingerMsg` with inner data stored in `msg` still encrypted.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PartialPongerMsg {
    session: Session,
    msg: Vec<u8>,
}

/// Fully decoded and decrypted reply to `PingerMsg`.
#[derive(Debug, PartialEq, Clone)]
pub struct PlaintextPongerMsg {
    session: Session,
    msg: Ponger,
}

impl PingerMsg {
    /// Create new ping packet (request)
    pub fn ping(wg_port: WGPort, session: Session, ts: Timestamp) -> Self {
        Self {
            session,
            msg: Pinger {
                start_timestamp: ts,
                wg_port: wg_port.0 as u32,
                ..Default::default()
            },
        }
    }

    /// Create new pong packet (response)
    pub fn pong(
        &self,
        wg_port: WGPort,
        ping_source: &IpAddr,
        ep_provider: EndpointProvider,
    ) -> Option<PlaintextPongerMsg> {
        match ping_source {
            IpAddr::V4(v4address) => Some(PlaintextPongerMsg {
                session: self.session,
                msg: Ponger {
                    start_timestamp: self.msg.get_start_timestamp(),
                    ping_source_address: Some(Ponger_oneof_ping_source_address::v4(u32::from(
                        *v4address,
                    ))),
                    wg_port: wg_port.0 as u32,
                    ponging_ep_provider: ep_provider.into(),
                    ..Default::default()
                },
            }),
            _ => None,
        }
    }

    /// Get WG Port
    pub fn get_wg_port(&self) -> WGPort {
        WGPort(self.msg.wg_port as u16)
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.session
    }

    /// Get ping start timestamp
    pub fn get_start_timestamp(&self) -> Timestamp {
        self.msg.get_start_timestamp()
    }

    /// Decode and decrypt `bytes` using `decrypt` function.
    pub fn decode_and_decrypt(
        bytes: &[u8],
        decrypt: impl FnOnce(
            PacketTypeRelayed,
            &[u8],
        ) -> Result<(Vec<u8>, Option<PublicKey>), CodecError>,
    ) -> CodecResult<(Self, Option<PublicKey>)>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        let packet_type =
            PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)));
        match packet_type {
            PacketTypeRelayed::Pinger => {
                let (bytes, public_key) = decrypt(
                    packet_type,
                    bytes.get(1..).ok_or(CodecError::InvalidLength)?,
                )?;
                let session = bytes
                    .get(0..8)
                    .ok_or(CodecError::InvalidLength)?
                    .try_into()
                    .map_err(|_| CodecError::InvalidLength)
                    .map(Session::from_be_bytes)?;
                let pinger =
                    Pinger::parse_from_bytes(bytes.get(8..).ok_or(CodecError::InvalidLength)?);
                Ok((
                    Self {
                        session,
                        msg: pinger.map_err(|_| CodecError::DecodeFailed)?,
                    },
                    public_key,
                ))
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    /// Encode and encrypt `self` using `encrypt` function.
    pub fn encode_and_encrypt(
        self,
        encrypt: impl FnOnce(&[u8]) -> CodecResult<Vec<u8>>,
    ) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut inner_bytes = Vec::with_capacity(MAX_PACKET_SIZE);
        inner_bytes.put_u64(self.session);
        self.msg
            .write_to_vec(&mut inner_bytes)
            .map_err(|_| CodecError::Encode)?;
        let transformed = encrypt(&inner_bytes)?;
        let mut bytes = Vec::with_capacity(1 + transformed.len());
        bytes.put_u8(PacketTypeRelayed::Pinger as u8);
        bytes.extend(transformed);
        Ok(bytes)
    }
}

impl Codec<PacketTypeRelayed> for PingerMsg {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::Pinger];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        Self::decode_and_decrypt(bytes, |_, b| Ok((b.to_vec(), None))).map(|(msg, _)| msg)
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        self.encode_and_encrypt(|b| Ok(b.to_vec()))
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::Pinger
    }
}

impl DowncastPacket<PacketRelayed> for PingerMsg {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::Pinger(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for PingerMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ping wg_port: {}, session: {}, start_ts: {}",
            self.get_wg_port().0,
            self.get_session(),
            self.get_start_timestamp()
        )
    }
}

impl PlaintextPongerMsg {
    /// Get WG Port
    pub fn get_wg_port(&self) -> WGPort {
        WGPort(self.msg.wg_port as u16)
    }

    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.session
    }

    /// Get ping start ts
    pub fn get_start_timestamp(&self) -> Timestamp {
        self.msg.get_start_timestamp()
    }

    /// Get source address of the ping packet as seen by the pinged node
    pub fn get_ping_source_address(&self) -> CodecResult<Ipv4Addr> {
        if self.msg.has_v4() {
            Ok(Ipv4Addr::from(self.msg.get_v4()))
        } else {
            Err(CodecError::DecodeFailed)
        }
    }

    /// Get ponging endpoint provider
    pub fn get_ponging_ep_provider(&self) -> CodecResult<Option<EndpointProvider>> {
        let ep_provider_raw = self.msg.get_ponging_ep_provider();
        if ep_provider_raw == 0 {
            Ok(None)
        } else {
            EndpointProvider::try_from(ep_provider_raw)
                .map_err(|_| CodecError::DecodeFailed)
                .map(Some)
        }
    }

    /// Encode and encrypt `self` using `encrypt` function.
    pub fn encode_and_encrypt(
        self,
        encrypt: impl FnOnce(&[u8]) -> CodecResult<Vec<u8>>,
    ) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut buf = Vec::with_capacity(MAX_PACKET_SIZE);
        self.msg
            .write_to_vec(&mut buf)
            .map_err(|_| CodecError::Encode)?;
        let transformed = encrypt(&buf)?;
        let mut bytes = Vec::with_capacity(1 + 8 + transformed.len());
        bytes.put_u8(PacketTypeRelayed::Ponger as u8);
        bytes.put_u64(self.session);
        bytes.extend(transformed);
        Ok(bytes)
    }
}

impl PartialPongerMsg {
    /// Decrypt `self` into `CompletePongerMsg` using `decrypt` function.
    pub fn decrypt(
        self,
        decrypt: impl FnOnce(&[u8]) -> CodecResult<Vec<u8>>,
    ) -> CodecResult<PlaintextPongerMsg> {
        let transformed = decrypt(&self.msg)?;
        let msg = Ponger::parse_from_bytes(&transformed).map_err(|_| CodecError::DecodeFailed)?;
        Ok(PlaintextPongerMsg {
            session: self.session,
            msg,
        })
    }
    /// Get unique session number
    pub fn get_session(&self) -> Session {
        self.session
    }

    /// Decode and decrypt `bytes` using `decrypt` function.
    pub fn decode_and_decrypt(
        bytes: &[u8],
        decrypt: impl FnOnce(
            PacketTypeRelayed,
            &[u8],
        ) -> Result<(Vec<u8>, Option<PublicKey>), CodecError>,
    ) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        let packet_type =
            PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)));
        match packet_type {
            PacketTypeRelayed::Ponger => {
                let session = bytes
                    .get(1..9)
                    .ok_or(CodecError::InvalidLength)?
                    .try_into()
                    .map_err(|_| CodecError::InvalidLength)
                    .map(Session::from_be_bytes)?;
                let (bytes, _) = decrypt(
                    packet_type,
                    bytes.get(9..).ok_or(CodecError::InvalidLength)?,
                )?;
                Ok(Self {
                    session,
                    msg: bytes,
                })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }
}

impl Codec<PacketTypeRelayed> for PartialPongerMsg {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::Ponger];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)))
        {
            PacketTypeRelayed::Ponger => {
                let session = bytes
                    .get(1..9)
                    .ok_or(CodecError::InvalidLength)?
                    .try_into()
                    .map_err(|_| CodecError::InvalidLength)
                    .map(Session::from_be_bytes)?;
                Ok(Self {
                    session,
                    msg: bytes.get(9..).ok_or(CodecError::InvalidLength)?.to_vec(),
                })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut bytes = Vec::with_capacity(1 + 8 + self.msg.len());
        bytes.put_u8(PacketTypeRelayed::Ponger as u8);
        bytes.put_u64(self.session);
        bytes.extend(self.msg);
        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::Ponger
    }
}

impl DowncastPacket<PacketRelayed> for PartialPongerMsg {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::Ponger(data) => Ok(data),
            packet => Err(packet),
        }
    }
}

impl std::fmt::Display for PartialPongerMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Partial Pong wg_port: session: {}, msg len: {}",
            self.session,
            self.msg.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_packet() {
        let ping_bytes = &[7, 0, 0, 0, 0, 0, 0, 0, 9, 8, 128, 2, 16, 8];
        let ping_data = PingerMsg::decode(ping_bytes).expect("Failed to parse packet");
        assert_eq!(ping_data.packet_type(), PacketTypeRelayed::Pinger);
        assert_eq!(ping_data.get_wg_port().0, 8_u16);
        assert_eq!(ping_data.get_session(), 9_u64);
        assert_eq!(ping_data.get_start_timestamp(), 256_u64);

        let ping_bytes = &[7, 0, 0, 0, 0, 0, 0, 0, 8, 8, 128, 4, 16, 6];
        let ping_data = PingerMsg::decode(ping_bytes).expect("Failed to parse packet");
        assert_eq!(ping_data.packet_type(), PacketTypeRelayed::Pinger);
        assert_eq!(ping_data.get_wg_port().0, 6_u16);
        assert_eq!(ping_data.get_session(), 8_u64);
        assert_eq!(ping_data.get_start_timestamp(), 512_u64);
    }

    #[test]
    fn decode_pong_packet() {
        let pong_bytes = &[
            9, 0, 0, 0, 0, 0, 0, 0, 8, 8, 42, 16, 3, 40, 3, 29, 1, 0, 0, 127,
        ];
        let pong_data =
            PartialPongerMsg::decode_and_decrypt(pong_bytes, |_, b| Ok((b.to_vec(), None)))
                .and_then(|partial_msg| partial_msg.decrypt(|v| Ok(v.to_vec())))
                .expect("Failed to parse packet");
        assert_eq!(pong_data.get_wg_port().0, 3_u16);
        assert_eq!(pong_data.get_session(), 8_u64);
        assert_eq!(pong_data.get_start_timestamp(), 42_u64);
        assert_eq!(
            pong_data
                .get_ping_source_address()
                .expect("Parsing IP address failed"),
            Ipv4Addr::from([127, 0, 0, 1])
        );
        assert_eq!(
            pong_data
                .get_ponging_ep_provider()
                .expect("Encoded endpoint provider is invalid"),
            Some(EndpointProvider::Upnp)
        );

        // We need to check also if we can parse correctly the legacy message (i.e. without ep type specified)
        let pong_bytes = &[9, 0, 0, 0, 0, 0, 0, 0, 8, 8, 42, 16, 3, 29, 1, 0, 0, 127];
        let pong_data =
            PartialPongerMsg::decode_and_decrypt(pong_bytes, |_, b| Ok((b.to_vec(), None)))
                .and_then(|partial_msg| partial_msg.decrypt(|v| Ok(v.to_vec())))
                .expect("Failed to parse packet");
        assert_eq!(pong_data.get_wg_port().0, 3_u16);
        assert_eq!(pong_data.get_session(), 8_u64);
        assert_eq!(pong_data.get_start_timestamp(), 42_u64);
        assert_eq!(
            pong_data
                .get_ping_source_address()
                .expect("Parsing IP address failed"),
            Ipv4Addr::from([127, 0, 0, 1])
        );
        assert_eq!(
            pong_data
                .get_ponging_ep_provider()
                .expect("Encoded endpoint provider is invalid"),
            None
        );
    }

    #[test]
    fn fail_to_decode_small_packet() {
        let bytes = &[];
        let data = PingerMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::InvalidLength));
    }

    #[test]
    fn fail_to_decode_packet_of_wrong_type() {
        let bytes = &[PacketTypeRelayed::Invalid as u8, 3, 1, 7, 6];
        let data = PingerMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_packet() {
        let ping = PingerMsg::ping(WGPort(2), 3_u64, 10_u64);
        let ping_bytes = b"\x07\x00\x00\x00\x00\x00\x00\x00\x03\x08\x0A\x10\x02";
        assert_eq!(ping.encode().unwrap(), ping_bytes);

        let ping = PingerMsg::ping(WGPort(2), 3_u64, 10_u64);
        let endpoint = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let pong = ping
            .pong(WGPort(3), &endpoint, EndpointProvider::Stun)
            .unwrap();
        let pong_bytes =
            b"\x09\x00\x00\x00\x00\x00\x00\x00\x03\x08\x0A\x10\x03\x28\x02\x1d\x01\x00\x00\x7f";
        assert_eq!(
            pong.encode_and_encrypt(|b| Ok(b.to_vec())).unwrap(),
            pong_bytes
        );
    }
}
