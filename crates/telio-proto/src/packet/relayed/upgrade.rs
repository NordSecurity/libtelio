use std::net::SocketAddr;

use crate::{
    messages::upgrade::*, Codec, CodecError, CodecResult, DowncastPacket, PacketRelayed,
    PacketTypeRelayed, Session, MAX_PACKET_SIZE,
};

use bytes::BufMut;
use protobuf::Message;

/// Packet encapsulating ugprade message
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UpgradeMsg {
    /// Endpoint which message sender is requesting to upgrade to
    pub endpoint: SocketAddr,
    /// Session id created by CrossPingCheck
    pub session: Session,
}

impl Codec<PacketTypeRelayed> for UpgradeMsg {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::Upgrade];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(CodecError::InvalidLength);
        }

        match PacketTypeRelayed::from(*bytes.first().unwrap_or(&(PacketTypeRelayed::Invalid as u8)))
        {
            PacketTypeRelayed::Upgrade => {
                let proto_upgrade =
                    Upgrade::parse_from_bytes(bytes.get(1..).ok_or(CodecError::DecodeFailed)?)
                        .map_err(|_| CodecError::DecodeFailed)?;
                let endpoint: SocketAddr = proto_upgrade
                    .get_endpoint()
                    .parse()
                    .map_err(|_| CodecError::DecodeFailed)?;
                let session: Session = proto_upgrade.session;

                Ok(Self { endpoint, session })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);
        let mut msg = Upgrade::new();
        msg.set_endpoint(self.endpoint.to_string());
        msg.set_session(self.session);

        bytes.put_u8(PacketTypeRelayed::Upgrade as u8);
        msg.write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::Upgrade
    }
}

impl DowncastPacket<PacketRelayed> for UpgradeMsg {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::Upgrade(upgrade) => Ok(upgrade),
            packet => Err(packet),
        }
    }
}

/// Decision of the other node if the upgrade request was accepted and performed
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Decision {
    /// Upgrade request was accepted and performed
    Accepted = 0,
    /// Upgrade request was rejected because it contained unknown session id
    RejectedDueToUnknownSession = 1,
    /// Upgrade request was rejected because it was sent when the other node has
    /// already also sent an upgrade request to us, and they have a winning pub key.
    RejectedDueToConcurrentUpgrade = 2,
}

impl From<crate::messages::upgrade::Decision> for Decision {
    fn from(value: crate::messages::upgrade::Decision) -> Self {
        match value {
            crate::messages::upgrade::Decision::Accepted => Decision::Accepted,
            crate::messages::upgrade::Decision::RejectedDueToUnknownSession => {
                Decision::RejectedDueToUnknownSession
            }
            crate::messages::upgrade::Decision::RejectedDueToConcurrentUpgrade => {
                Decision::RejectedDueToConcurrentUpgrade
            }
        }
    }
}

impl From<Decision> for crate::messages::upgrade::Decision {
    fn from(value: Decision) -> Self {
        use crate::messages::upgrade::Decision::*;
        match value {
            Decision::Accepted => Accepted,
            Decision::RejectedDueToUnknownSession => RejectedDueToUnknownSession,
            Decision::RejectedDueToConcurrentUpgrade => RejectedDueToConcurrentUpgrade,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// Result of previously sent upgrade request
pub struct UpgradeDecisionMsg {
    /// Decision if the upgrade was accepted and processed
    pub decision: Decision,
    /// Session identifing request for which this result in an answer
    pub session: Session,
}

impl Codec<PacketTypeRelayed> for UpgradeDecisionMsg {
    const TYPES: &'static [PacketTypeRelayed] = &[PacketTypeRelayed::UpgradeDecision];

    fn decode(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        let Some((first, rest)) = bytes.split_first() else {
            return Err(CodecError::InvalidLength);
        };
        match PacketTypeRelayed::from(*first) {
            PacketTypeRelayed::UpgradeDecision => {
                let proto_upgrade_decision = UpgradeDecision::parse_from_bytes(rest)
                    .map_err(|_| CodecError::DecodeFailed)?;
                let decision: Decision = proto_upgrade_decision.get_decision().into();
                let session: Session = proto_upgrade_decision.session;

                Ok(Self { decision, session })
            }
            _ => Err(CodecError::DecodeFailed),
        }
    }

    fn encode(self) -> CodecResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut bytes = Vec::with_capacity(MAX_PACKET_SIZE);
        let mut msg = UpgradeDecision::new();
        msg.set_decision(self.decision.into());
        msg.set_session(self.session);

        bytes.put_u8(PacketTypeRelayed::UpgradeDecision as u8);
        msg.write_to_vec(&mut bytes)
            .map_err(|_| CodecError::Encode)?;

        Ok(bytes)
    }

    fn packet_type(&self) -> PacketTypeRelayed {
        PacketTypeRelayed::UpgradeDecision
    }
}

impl DowncastPacket<PacketRelayed> for UpgradeDecisionMsg {
    fn downcast(packet: PacketRelayed) -> Result<Self, PacketRelayed>
    where
        Self: Sized,
    {
        match packet {
            PacketRelayed::UpgradeDecision(upgrade_decision) => Ok(upgrade_decision),
            packet => Err(packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_upgrade_packet() {
        let upgrade_bytes = &[
            8, 10, 14, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 50, 51, 52, 17, 42, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let upgrade_msg = UpgradeMsg::decode(upgrade_bytes).expect("Failed to parse upgrade msg");
        assert_eq!(upgrade_msg.endpoint, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(upgrade_msg.session, 42);
    }

    #[test]
    fn fail_to_decode_small_upgrade_packet() {
        let bytes = &[6];
        let data = UpgradeMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn fail_to_decode_upgrade_packet_of_wrong_type() {
        let bytes = &[PacketTypeRelayed::Invalid as u8];
        let data = UpgradeMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_upgrade_packet() {
        let upgrade_msg = UpgradeMsg {
            endpoint: "127.0.0.1:1234".parse().unwrap(),
            session: 42,
        };
        let expected_upgrade_bytes: &[u8] = &[
            8, 10, 14, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 50, 51, 52, 17, 42, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let actual_upgrade_bytes = upgrade_msg.encode().unwrap();
        assert_eq!(expected_upgrade_bytes, actual_upgrade_bytes);
    }

    #[test]
    fn decode_upgrade_decision_packet() {
        let upgrade_bytes = &[10, 17, 42, 0, 0, 0, 0, 0, 0, 0];
        let upgrade_msg =
            UpgradeDecisionMsg::decode(upgrade_bytes).expect("Failed to parse upgrade msg");
        assert_eq!(upgrade_msg.decision, Decision::Accepted);
        assert_eq!(upgrade_msg.session, 42);
    }

    #[test]
    fn fail_to_decode_small_upgrade_decision_packet() {
        let bytes = &[6];
        let data = UpgradeDecisionMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn fail_to_decode_upgrade_decision_packet_of_wrong_type() {
        let bytes = &[PacketTypeRelayed::Invalid as u8];
        let data = UpgradeDecisionMsg::decode(bytes);
        assert_eq!(data, Err(CodecError::DecodeFailed));
    }

    #[test]
    fn encode_upgrade_decision_packet() {
        let upgrade_msg = UpgradeDecisionMsg {
            decision: crate::Decision::RejectedDueToUnknownSession,
            session: 42,
        };
        let expected_upgrade_bytes: &[u8] = &[10, 8, 1, 17, 42, 0, 0, 0, 0, 0, 0, 0];

        let actual_upgrade_bytes = upgrade_msg.clone().encode().unwrap();
        assert_eq!(expected_upgrade_bytes, actual_upgrade_bytes);

        assert_eq!(
            upgrade_msg,
            UpgradeDecisionMsg::decode(&actual_upgrade_bytes).unwrap()
        );
    }
}
