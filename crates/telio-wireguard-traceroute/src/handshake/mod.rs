#[cfg(test)]
mod zero_rng_crypto_resolver;

use anyhow::Result;
use blake2::{Blake2s256, Digest};
use snow::{
    Builder,
    resolvers::{BoxedCryptoResolver, DefaultResolver},
};

const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

/// Generates a WireGuard handshake initiation packet using snow (Noise framework)
///
/// # Arguments
/// * `self_private_key` - The initiator's private key (32 bytes)
/// * `peer_public_key` - The responder's public key (32 bytes)
///
/// # Returns
/// A Vec<u8> containing the complete handshake initiation packet (148 bytes)
pub fn create_handshake_initiation(
    self_private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    create_handshake_initiation_with_resolver(
        self_private_key,
        peer_public_key,
        Box::new(DefaultResolver::default()),
        get_tai64n_timestamp()?,
    )
}

fn create_handshake_initiation_with_resolver(
    self_private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    resolver: BoxedCryptoResolver,
    tai64n_timestamp: [u8; 12],
) -> Result<Vec<u8>> {
    // Generate sender index
    let mut sender_index_bytes = [0u8; 4];
    resolver
        .resolve_rng()
        .map(|mut rng| rng.try_fill_bytes(&mut sender_index_bytes));
    let sender_index = u32::from_ne_bytes(sender_index_bytes);

    // Build Noise handshake state
    let builder = Builder::with_resolver(NOISE_PARAMS.parse()?, resolver)
        .local_private_key(self_private_key)?
        .remote_public_key(peer_public_key)?
        .prologue(IDENTIFIER)?;

    let mut noise = builder.build_initiator()?;

    // Prepare message buffer
    let mut packet = Vec::with_capacity(148);

    // Message type (1 = handshake initiation)
    packet.push(1u8);

    // Reserved (3 bytes)
    packet.extend_from_slice(&[0u8; 3]);

    // Sender index (4 bytes, little-endian)
    packet.extend_from_slice(&sender_index.to_le_bytes());

    // Generate noise message
    let mut temp_buffer = vec![0u8; 108];
    let len = noise.write_message(&tai64n_timestamp, &mut temp_buffer)?;

    packet.extend_from_slice(&temp_buffer[..len]);

    // Calculate MAC1
    let mac1 = calculate_mac1(&packet, peer_public_key)?;
    packet.extend_from_slice(&mac1);

    // MAC2 (zeros)
    packet.extend_from_slice(&[0u8; 16]);

    assert_eq!(packet.len(), 148, "Packet must be exactly 148 bytes");

    Ok(packet)
}

fn get_tai64n_timestamp() -> Result<[u8; 12]> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let tai64_base: u64 = (1u64 << 62) + now.as_secs();
    let nanoseconds: u32 = now.subsec_nanos();

    let mut timestamp = [0u8; 12];
    timestamp[0..8].copy_from_slice(&tai64_base.to_be_bytes());
    timestamp[8..12].copy_from_slice(&nanoseconds.to_be_bytes());

    Ok(timestamp)
}

/// Calculate MAC1 field using BLAKE2s keyed hash
fn calculate_mac1(packet_without_macs: &[u8], peer_public_key: &[u8; 32]) -> Result<[u8; 16]> {
    use blake2::Blake2sMac;
    use blake2::digest::consts::U16;
    use blake2::digest::{FixedOutput, KeyInit, Update};

    // Derive MAC1 key: HASH(LABEL_MAC1 || peer_public_key)
    let mut hash = Blake2s256::new();
    Digest::update(&mut hash, LABEL_MAC1);
    Digest::update(&mut hash, peer_public_key);
    let mac_key = hash.finalize();

    // Use BLAKE2s in keyed mode
    let mut keyed_hash = Blake2sMac::<U16>::new_from_slice(&mac_key).expect("Key size is valid");
    keyed_hash.update(&packet_without_macs[..116]);
    let result = keyed_hash.finalize_fixed();

    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&result);
    Ok(mac1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_generation() {
        let self_private_key = [1u8; 32];
        let peer_public_key = [2u8; 32];

        let packet = create_handshake_initiation(&self_private_key, &peer_public_key).unwrap();

        assert_eq!(packet.len(), 148);
        assert_eq!(packet[0], 1);
        assert_eq!(&packet[1..4], &[0, 0, 0]);
    }

    #[test]
    fn test_handshake_generation_with_zero_rng() {
        use zero_rng_crypto_resolver::ZeroRngCryptoResolver;

        let self_private_key = [1u8; 32];
        let peer_public_key = [2u8; 32];
        let tai64n_timestamp = [3u8; 12];

        let packet = create_handshake_initiation_with_resolver(
            &self_private_key,
            &peer_public_key,
            Box::new(ZeroRngCryptoResolver),
            tai64n_timestamp,
        )
        .unwrap();

        assert_eq!(
            packet,
            [
                1, // message_type
                0, 0, 0, // reserved_zero[3]
                0, 0, 0, 0, // sender_index
                47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246,
                132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59,
                116, // unencrypted ephemeral[32]
                132, 115, 202, 231, 146, 16, 248, 147, 110, 113, 27, 13, 101, 94, 228, 212, 75,
                194, 65, 39, 130, 54, 28, 149, 12, 55, 119, 14, 181, 158, 235, 214, 234, 229, 240,
                54, 243, 167, 106, 79, 249, 125, 146, 227, 215, 241, 122,
                170, // encrypted_static[32+16]
                4, 47, 169, 213, 25, 48, 1, 215, 191, 143, 140, 227, 65, 111, 158, 100, 54, 50, 36,
                208, 111, 30, 181, 47, 247, 126, 121, 124, // encrypted_timestamp[12+16]
                118, 30, 175, 97, 167, 56, 96, 72, 242, 114, 165, 132, 166, 158, 248,
                148, // mac1
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // mac2
            ]
        );
    }
}
