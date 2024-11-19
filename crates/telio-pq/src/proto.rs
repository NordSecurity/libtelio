use std::{
    io::{self, Read},
    net::Ipv4Addr,
    ops::RangeInclusive,
    time::{Duration, SystemTime},
};

use blake2::Digest;
use boringtun::noise;
use hmac::Mac;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::{prelude::Distribution, rngs::OsRng};
use telio_utils::telio_log_debug;
use tokio::net::{ToSocketAddrs, UdpSocket};

const SERVICE_PORT: u16 = 6480;
const LOCAL_PORT_RANGE: RangeInclusive<u16> = 49152..=u16::MAX; // dynamic port range
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 1);
const PQ_PROTO_VERSION: u32 = 1;
const CIPHERTEXT_LEN: u32 = kyber768::ciphertext_bytes() as _;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

const RECV_TIMEOUT: Duration = Duration::from_secs(4);

struct TunnelSock {
    tunn: noise::Tunn,
    sock: UdpSock<telio_sockets::External<UdpSocket>>,
}

// A newtype to enfore usage of custom `recv()` call with timeout
struct UdpSock<T>(T);

pub struct KeySet {
    pub wg_keys: super::Keys,
    pub pq_secret: kyber768::SecretKey,
}

/// Get PQ keys from the VPN server
/// The packet sequence is as follows
///
/// 1) C -> S             : Client sends WG hansake packet                           
/// 2) S -> C             : Server responds to handsake                              
/// 3) C -> S (in tunnel) : Client sends a UDP PQ GET packet with keys               
/// 4) S -> C (in tunnel) : Server responds with UDP packet containing the ciphertext
///
/// The shared key is established which should be used as,
/// a WG preshared key for subsequent connection
pub async fn fetch_keys(
    sock_pool: &telio_sockets::SocketPool,
    endpoint: impl ToSocketAddrs,
    secret: &telio_crypto::SecretKey,
    peers_pubkey: &telio_crypto::PublicKey,
) -> super::Result<KeySet> {
    telio_log_debug!("Fetching keys");
    let TunnelSock { mut tunn, sock } =
        handshake(sock_pool, endpoint, secret, peers_pubkey).await?;
    telio_log_debug!("Initial WG handshake done");

    let mut rng = OsRng;

    // Generate keys
    let wg_secret = telio_crypto::SecretKey::gen_with(&mut rng);
    let (pq_public, pq_secret) = kyber768::keypair();
    let wg_public = telio_crypto::PublicKey::from(&wg_secret);

    // Send GET packet
    let pkgbuf = create_get_packet(peers_pubkey, &wg_secret, &wg_public, &pq_public, &mut rng); // 4 KiB

    let mut recvbuf = [0u8; 2048]; // 2 KiB buffer should suffice
    match tunn.encapsulate(&pkgbuf, &mut recvbuf) {
        noise::TunnResult::Err(err) => {
            return Err(format!("Failed to encapsulate PQ keys message: {err:?}").into())
        }
        noise::TunnResult::WriteToNetwork(buf) => {
            telio_log_debug!("Sending handshake packet");
            sock.send(buf).await?;
        }
        _ => return Err("Unexpected WG tunnel output".into()),
    }

    // Receive response
    let pkg = sock.recv(&mut recvbuf).await?;
    telio_log_debug!("Received packet of size {}", pkg.len());

    let mut msgbuf = [0u8; 2048]; // 2 KiB buffer should shuffice

    #[allow(index_access_check)]
    let ciphertext = match tunn.decapsulate(None, pkg, &mut msgbuf) {
        noise::TunnResult::Err(err) => {
            return Err(format!("Failed to decapsulate PQ keys message: {err:?}").into())
        }
        noise::TunnResult::WriteToTunnelV4(buf, _) => parse_get_response(buf)?,
        _ => return Err("Unexpected WG tunnel output".into()),
    };

    // Extract the shared secret
    let pq_shared = kyber768::decapsulate(&ciphertext, &pq_secret);
    let pq_shared = telio_crypto::PresharedKey::new(
        pq_shared
            .as_bytes()
            .try_into()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
    );

    Ok(KeySet {
        wg_keys: super::Keys {
            pq_shared,
            wg_secret,
        },
        pq_secret,
    })
}

/// Establsh new PQ preshared key with the VPN server
pub async fn rekey(
    sock_pool: &telio_sockets::SocketPool,
    pq_secret: &kyber768::SecretKey,
) -> super::Result<telio_crypto::PresharedKey> {
    telio_log_debug!("Rekeying");
    let mut pkgbuf = Vec::with_capacity(1024 * 4); // 4 KiB
    push_rekey_method_udp_payload(&mut pkgbuf);

    let sock = UdpSock::internal(sock_pool, (REMOTE_IP, SERVICE_PORT)).await?;

    telio_log_debug!("Sending rekey request");
    sock.send(&pkgbuf).await?;

    let mut recvbuf = [0u8; 2048];
    let pkg = sock.recv(&mut recvbuf).await?;
    telio_log_debug!("Received packet of size {}", pkg.len());

    #[allow(index_access_check)]
    let ciphertext = parse_response_payload(pkg)?;

    // Extract the shared secret
    let pq_shared = kyber768::decapsulate(&ciphertext, pq_secret);
    let pq_shared = telio_crypto::PresharedKey::new(
        pq_shared
            .as_bytes()
            .try_into()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
    );

    Ok(pq_shared)
}

async fn handshake(
    sock_pool: &telio_sockets::SocketPool,
    endpoint: impl ToSocketAddrs,
    secret: &telio_crypto::SecretKey,
    peers_pubkey: &telio_crypto::PublicKey,
) -> super::Result<TunnelSock> {
    let sock = UdpSock::external(sock_pool, endpoint).await?;

    let mut tunn = noise::Tunn::new(
        secret.into_bytes().into(),
        peers_pubkey.0.into(),
        None,
        None,
        0,
        None,
    )?;

    let mut pkgbuf = [0u8; 2048];
    match tunn.encapsulate(&[], &mut pkgbuf) {
        noise::TunnResult::Err(err) => {
            return Err(format!("Failed to encapsulate handshake message: {err:?}").into())
        }
        noise::TunnResult::WriteToNetwork(buf) => {
            telio_log_debug!("Sending WG handshake");
            sock.send(buf).await?;
        }
        _ => return Err("Unexpected WG tunnel output".into()),
    }

    // The response should be 92, so the buffer is sufficient
    let pkg = sock.recv(&mut pkgbuf).await?;
    telio_log_debug!("Handshake response received");

    let mut msgbuf = [0u8; 2048];

    #[allow(index_access_check)]
    match tunn.decapsulate(None, pkg, &mut msgbuf) {
        noise::TunnResult::Err(err) => {
            return Err(format!("Failed to decapsulate handshake message: {err:?}").into())
        }
        noise::TunnResult::WriteToNetwork(_) => {
            // This is a outgoing keep alive message, we can skip sending it for the hanshake
        }
        _ => return Err("Unexpected WG tunnel output".into()),
    }

    Ok(TunnelSock { tunn, sock })
}

pub fn parse_get_response(pkgbuf: &[u8]) -> super::Result<kyber768::Ciphertext> {
    let ip = Ipv4Packet::new(pkgbuf).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys IP packet received",
    ))?;

    let udp = UdpPacket::new(ip.payload()).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys UDP packet received",
    ))?;

    parse_response_payload(udp.payload())
}

/// The response looks as follows:
///
/// ---------------------------------
///  version           , u32le, = 1
/// ---------------------------------
///  Ciphertext len    , u32le, = 1088
/// ---------------------------------
///  Ciphertext bytes  , [u8]
/// ---------------------------------
pub fn parse_response_payload(payload: &[u8]) -> super::Result<kyber768::Ciphertext> {
    let mut data = io::Cursor::new(payload);

    let mut version = [0u8; 4];
    data.read_exact(&mut version)?;
    let version = u32::from_le_bytes(version);
    if version != PQ_PROTO_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server responded with invalid PQ handshake version",
        )
        .into());
    }

    let mut ciphertext_len = [0u8; 4];
    data.read_exact(&mut ciphertext_len)?;
    let ciphertext_len = u32::from_le_bytes(ciphertext_len);

    if ciphertext_len != CIPHERTEXT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server responded with invalid PQ handshake ciphertext lenght",
        )
        .into());
    }

    let mut cipherbuf = [0; CIPHERTEXT_LEN as usize];
    data.read_exact(&mut cipherbuf)?;

    let ct = kyber768::Ciphertext::from_bytes(&cipherbuf)
        .map_err(|err| format!("Invalid PQ ciphertext received: {err:?}"))?;

    Ok(ct)
}

fn create_get_packet(
    wg_server_public: &telio_crypto::PublicKey,
    wg_client_secret: &telio_crypto::SecretKey,
    wg_client_public: &telio_crypto::PublicKey,
    pq_public: &kyber768::PublicKey,
    rng: &mut impl rand::Rng,
) -> Vec<u8> {
    let mut pkgbuf = Vec::with_capacity(1024 * 4); // 4 KiB
    pkgbuf.resize(IPV4_HEADER_LEN + UDP_HEADER_LEN, 0);

    push_get_method_udp_payload_without_auth_tag(&mut pkgbuf, wg_client_public, pq_public);

    #[allow(index_access_check)]
    let to_hash = &pkgbuf[IPV4_HEADER_LEN + UDP_HEADER_LEN..];

    let tag = {
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let shared_secret = x25519_dalek::x25519(*wg_client_secret.as_bytes(), wg_server_public.0);

        #[allow(clippy::expect_used)]
        let mut hmac =
            HmacSha256::new_from_slice(&shared_secret).expect("HMAC can take key of any size");
        hmac.update(&blake2::Blake2s256::digest(to_hash));
        hmac.finalize().into_bytes()
    };
    pkgbuf.extend_from_slice(&tag);

    fill_get_packet_headers(pkgbuf.as_mut_slice(), rng);

    pkgbuf
}

/// The GET payload looks as follows:
///
/// ---------------------------------
///  version           , u32le, = 1
/// ---------------------------------
///  method            , u32le, = 0
/// ---------------------------------
///  timestamp         , u64le
/// ---------------------------------
///  WG pubkey len     , u32le, = 32
/// ---------------------------------
///  WG pubkey bytes   , [u8]
/// ---------------------------------
///  Kyber pubkey len  , u32le, = 1184
/// ---------------------------------
///  Kyber pubkey bytes, [u8]
/// ---------------------------------
///  Authentication tag, [u8; 32]
/// ---------------------------------
///
/// But this function does not include `Authentication tag`
fn push_get_method_udp_payload_without_auth_tag(
    pkgbuf: &mut Vec<u8>,
    wg_public: &telio_crypto::PublicKey,
    pq_public: &kyber768::PublicKey,
) {
    let method = 0u32; // get
    let timestamp: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // UDP packet payload
    pkgbuf.extend_from_slice(&PQ_PROTO_VERSION.to_le_bytes());
    pkgbuf.extend_from_slice(&method.to_le_bytes());
    pkgbuf.extend_from_slice(&timestamp.to_le_bytes());
    pkgbuf.extend_from_slice(&(wg_public.len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(wg_public);
    pkgbuf.extend_from_slice(&(pq_public.as_bytes().len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(pq_public.as_bytes());
}

/// The REKEY payload looks as follows:
///
/// --------------------------------
///  version           , u32le, = 1
/// --------------------------------
///  method            , u32le, = 1
/// ---------------------------------
fn push_rekey_method_udp_payload(pkgbuf: &mut Vec<u8>) {
    let method = 1u32; // rekey

    // UDP packet payload
    pkgbuf.extend_from_slice(&PQ_PROTO_VERSION.to_le_bytes());
    pkgbuf.extend_from_slice(&method.to_le_bytes());
}

/// Sets up UDP and IP headers in the provided buffer
///
/// # Panics
///
/// Panics if the buffer size is less than IP + UDP headers bytes.
fn fill_get_packet_headers(pkgbuf: &mut [u8], rng: &mut impl rand::Rng) {
    let pkg_len = pkgbuf.len();

    #[allow(clippy::expect_used)]
    #[allow(index_access_check)]
    let mut udppkg = MutableUdpPacket::new(&mut pkgbuf[IPV4_HEADER_LEN..])
        .expect("UDP buffer should not be too small");
    udppkg.set_source(random_port(rng));
    udppkg.set_destination(SERVICE_PORT);
    udppkg.set_length((pkg_len - IPV4_HEADER_LEN) as _);
    udppkg.set_checksum(udp::ipv4_checksum(
        &udppkg.to_immutable(),
        &LOCAL_IP,
        &REMOTE_IP,
    ));
    drop(udppkg);

    #[allow(clippy::expect_used)]
    #[allow(index_access_check)]
    let mut ippkg = MutableIpv4Packet::new(&mut pkgbuf[..IPV4_HEADER_LEN])
        .expect("IPv4 buffer should not be too small");
    ippkg.set_version(4);
    ippkg.set_header_length(5);
    ippkg.set_total_length(pkg_len as _);
    ippkg.set_flags(Ipv4Flags::DontFragment);
    ippkg.set_ttl(0xFF);
    ippkg.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ippkg.set_source(LOCAL_IP);
    ippkg.set_destination(REMOTE_IP);
    ippkg.set_checksum(ipv4::checksum(&ippkg.to_immutable()));
}

impl UdpSock<telio_sockets::External<UdpSocket>> {
    async fn external(
        sock_pool: &telio_sockets::SocketPool,
        remote: impl ToSocketAddrs,
    ) -> super::Result<Self> {
        let sock = sock_pool
            .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
            .await?;
        sock.connect(remote).await?;
        Ok(Self(sock))
    }
}

impl UdpSock<UdpSocket> {
    async fn internal(
        sock_pool: &telio_sockets::SocketPool,
        remote: impl ToSocketAddrs,
    ) -> super::Result<Self> {
        let sock = sock_pool
            .new_internal_udp((Ipv4Addr::UNSPECIFIED, 0), None)
            .await?;
        sock.connect(remote).await?;
        Ok(Self(sock))
    }
}

trait UdpSockRef {
    fn sock(&self) -> &UdpSocket;
}

impl UdpSockRef for telio_sockets::External<UdpSocket> {
    fn sock(&self) -> &UdpSocket {
        self
    }
}

impl UdpSockRef for UdpSocket {
    fn sock(&self) -> &UdpSocket {
        self
    }
}

impl<T> UdpSock<T>
where
    T: UdpSockRef,
{
    async fn send(&self, buf: &[u8]) -> super::Result<()> {
        self.0.sock().send(buf).await?;
        Ok(())
    }

    async fn recv<'a>(&self, buf: &'a mut [u8]) -> super::Result<&'a [u8]> {
        let read = tokio::time::timeout(RECV_TIMEOUT, self.0.sock().recv(buf)).await??;

        #[allow(index_access_check)]
        Ok(&buf[..read])
    }
}

fn random_port(rng: &mut impl rand::Rng) -> u16 {
    rand::distributions::Uniform::new_inclusive(LOCAL_PORT_RANGE.start(), LOCAL_PORT_RANGE.end())
        .sample(rng)
}

#[cfg(test)]
mod tests {
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret};

    #[test]
    // The Kyber KEM has two competing algorithms and the library we're using changed the algorithm in their new version.
    // The test here is for capturing the eventual regression when the library is updated for example.
    fn decapsulate_kyber_ciphertext() {
        let secret_key = "e4GyMtQVorJvBtpRTeJAazMEnXg5dqwBexBXDTSwBbwuMUJLPDVktyWFzFhBa9NOr1ISwSGuHhmx1bQPWqhGv6ds4xZu9OtZLlsoRCJI/cKRmJBb1HNcyWUYFMV33BGcofxjggml00zISWux8ntAYWQkQ4GL8GaN1xxTjJdnZ4qyMPFQpTCvFMo0Gwu8uoxWmQQAiffEaiZfetNWwkYJ+YFW4Hm82ZYsXmgAb1IQ3RYQRTW7DGor8CKy8rkYTwVgT6GptArKClM+AWiRCQDL5PIGtyoyUUJVmSpyRNZFEPwY1nJOIVBqSeA/ZNMI8vCfhoAKFhfEhKMem3KpKvJYlJOC+0JMHAQQOntilDyY9Cc1sJxdbcNWIlo5IVhLW3FxD7dJ0HPDg9dhYXxyqjMAvHhCF2kUcSgdrFViV0LEe1rOweKFdJkyRKGo2va57ltz0IB00hIEFiRmavCkCXeWtEmIa/YrH7EBjOhNNWZ9GoOtuclWIoZeh0XNNZA0eySiCTWXL1QPTyhF9oeDV1dzNOKm7UCiPpNku7CVGMOF1FM1olBqG4soDKfN/RIsc/oV96S4GlK5IIgF/kDO4ryNOVFX0pl/Kls6koq5P9sVnzsGR4cGAuWU3RZdaKMu6BtEFXZh6VEqb/tAOtE3Mad2byYNOpOsIlhDX0awLhcbQRVVokQEyCKIx5OBqefJ1iNMEuiOj6ZT+FZPyRyyXXwM/FtugXQAX1ow+ge/PpWwAZvFkoFPh4OLyIpJT3U2GpKp5dKd/fZEiKdLX0SM7xoD1HcKXAqud1p0UmyfqLFZgCkVM/tDTthbz7Wk6ilGo9eyMNeAcKOWRwR71WDNzPUgqYzB+Ox600miwtYzHlillIZMelO/zBdypzZFrZhGynMAmxxMtKiXTbtkELxFMzpQTHhvuxSFfbFRJnoHYDYlprYP8xul8SCQDEQLwZdkVfwzE5qzGZw/YvogPUkSEbBSoEAqonYDg9WnYdaNKkeK83yGkLV5vOcUVKc4utstr6vJbGA1Bype34DFZeouqBEgWHMywXkPZ2dSXgVP/vl9gwRNErxpvDVfQIFZ3cFPdIQgt4bJx1sRYUvKKsOeNJtjk/KFzfDMkje2ogKPz8iTYnBRzWfOnPUIhDI/QZhSoAEYxwTNJvunyKlPYjCuG7U1z0M5UNVw7QuyiaumxOy0dGFNKraN8JTDqbgoC6xaWfCZR0qybkE0tceOhaa+8ZsigaxnqGh4gjErkpnMvUGKXAAVsLbHlygOEgd1u8tl46ERZzxdr1t0JTrJnxayCnwiW1ywqfk1gPd0hcg2k7goZJDNW4Aet3OsboRtLGUNE5xChMzBsnVVCxBH4aV/HHgmFbds4xeVLXC/sUlpMFgeahPMQvFeMSUgPWYmhAbPvMUTrCZPuwcGzQKZMdN7P3YJ4Is7KHOs1ddc3PxM6zC7/AOjBEkecIWp9GlDRUhVQHIqV1R1OiczeLky5YA5VqlgOEhY9qIzI+lrGVMGfRiu/PHBcxiq/lhItIRNupgRBzKOyKooKVJxS5hBJVyTNZiOICNswiKRhaEmfrGkBEE4XLE3uLlvwxUyo4C5kIFPq3xw0uRbK8U6CANRaTskM6swRCV3MMupGwcHI7dY7eUfJoGFaFyOQFqCqKWsjGC7qxqJbVYRWyFLLAin3SKiKwpgGwyKxGdt1hSH32R86DI04TR7SRwqMLqIbNVKX8qRIKd0KmdTHLp39XGm2iAHWSo2FgI8WoC0lLdIv3OcQYZMILJjAQJPaiR62MfOJpkf6uYpRlHBbIQnEjbGRUikmzYlsCxHu/wT0llZBjaL7rrBxQux71eCu6cqKvi7xkMH0gu5QAdOcmUbCswBQOJYwDqBSxMlJmyM7pM7aJhF62xQ1UMf8iexWhokltnMAXN0wqG0V8pI1DKLyncymyYYUjS6jxC9lQuD+3zEAPy2ZHOXbpe4DBMGzdBsGnzPUVJOlFcXPMYbjoVNEbhqhhCydnVhafidbPe4tFDFJdtDhQhNtjCK/VS0vDrKmSErWaKBhYSgKxYDtCDB/0CdKnC6EJwmoJUSLMtw/eFNCll3KFOE51EKkXg6KuYQiOzCIoE5P8w3LyZotUm9gohhXvsl8pZD9oFsl0YQUEd6Qqkbrqa8gSdL7ABWwpI+b1IdTYYB68QgU6OkpnMt7wXEGaxsnYY1aYWJARk+vkdmaLNFsCoxcOnFv6Z24cmfGBEe0LB/HsV2DREmzbUSIcVwjZsGOLMqcsCq+bCD8eWEeIu8wamiwUGmGVMTwFOxMjMPEBKhvLa2UthpEeEuPLwNjbg0AtyCL4p0/5Qo2tS0YphM+5GlrCJkjVwbfHmAnHivXlzCK9hNchqo5URXlHJOjehD2WSvBIvPQCi9IYAgSMAd/BNrq1eDCCzAOoali5QswxPD22AbHfrBkBWXy9JTyZJCExwRP5ZVTjIPSGKC++uVBce8aDZ+kVKPP1GOsXqxVikC0xVOfyMTCDN2/qSUMAcBMCaiEgSTFZdyyvgrHsVntJOHw9h1HaupMxuXuSNo5ms2zOCaTOiKR4tZYSMCxTaRLNRlLnPEHvsRxyFE1DpmIIPKn3KUt9kaUWM+ovwJy4tHu4nMUPJfsGem+ccsQdDE80uwJtLFeUC845FQC+HLoLecoNzOfhghxVcGhsyEUUIbRKmlOgEtI7OpmuSWB9xqocirBTx05ZI/f5lzqtgUXRiRx9wxCgoFZlY/33o2qieSLxlV5afEYCuKqIxE93aQmvcNkDwZbyNOD/IJV2g+3Ks4JEqlR0YLqPNyj4qomzp+IOY/hDgeftoJUKcxTUWDZXYmuIAjH1CSBgm4l+o9hHWGl1pl3LIGn1KNMhK5A1yNX3AqCHl6J8gjAcw3XKSmMMRZPEdMlFgVTLcicWSd6iZ1NyvO+fM8bkOKR7Gn6ekPzspztVtwl1ayzYXLMWRUdOhqtWtukCarIEXFyFG8ByKlsVQCRvKMSUCjp0eRHoIP/SnMGUufs1ZCM5ejwXZR/EK6XoNmyNQUrrVNGuB/2sm9Z/FLEEwShFiVlYMXvGFcZubPr03TqybQWtkXQ0KQxvxhLgLsk495B3i13F342yT5m1OX3Wor1JNyV6nAolgf/IDQGyXh9fBzETTooRcbl8jLfllhVDimPrZMw7488eXXw9qet8DIjUCP4UQ3B4R/jsSx";
        let ciphertext = "1PXYvRAU31rbjedEJLRVRiNVShRNt9RrBar0hzN4iqBQuSBYyVwZy4FwMHRQz5cnljn5gsQlUP3+jhkYL5YQqNy//oJtBwCz2NWzjXu2BzphKJaGE9FbBmvpwhTa70BdYbCri11GOK+bO6dpTTFaF0NqMhdDlMuvD9yv93RzTNfoZtVuqjTGvitx2bY+aCshir8mZ9iox3kyxcf8OIR7mFjUNQgRPgmvdmYSHqFuvaOSWQjxlzdkG0V3zlUr7IUusGLYFDSMqHPqMbm2HTWcaF7UsF/NwrUcUsm2mxev7QBu7nIBWQzMmnWacH6/0cxj/AOfv8TsdK6QUYrSYUFTHVWkbXwodpG4/5kzt6z4BhqS7d3Z30Pg4K+PA/5yQseGpgADOZlHfoqEysdDZ7Y+dypaXVX2Z6kUokwIcxKglJQYUTezGwUztukiTSVoTJ2osTJ5LnU3quuP/NZmdKdsuUs0fBaPTQ7gl2gaxc3LhXjmOPvU8VNZf0hJNlA91h6RCgCbn0z634I8LmCr94TZa1GJcIy7JvKZC2g9XhoIdjSuDuzjH0T7qixqZwib+wGzUJ5Mcz+SIMCwpSIALxsyOfuB5/E2eLnbtt1TWwMCq1O6HSgjDD2dT0qV3AQ9ZKkbggfjG53npNfK82zufBPhWphTly6Fv9yCWguXH/9pK46MnBUVWeiB1RQFl9/R/oflkg5Mlqe07lmBNWotYlg14IVG+ZF69jKtp6dIBe2bWzvH4SYn/2bhpwGGWZUQ1ZkoZvY6dUqglhnTzmBgXdXLSVDueVklXg1saHIFWYug/Friy+U5mU6AxYs1uEqfdf7x1GWbHjyHsaDG1WSGx2xHQ+5nvGsM7a9LR83BMtiFgJe9cWxPvYdD16FZEbax9uu1kgY+3ESgjJXY5uTD7igx0SuR+Q6DBc+7GwFY7Ox9U1FHUg2+mAV4QTh/gsA1d2FXkORbs/1GUMP8cjkmOyIVaNegPYPgsF22UyNbE3h25biTY+XbP3x9E2fCDGGB4XTG8muwBljndoiBuyp0xyCZ1IGl3siS13RXCJbkY7hFLVyOWExHZB2hQ6TX6a7wLP88YtbKcJK9viyixWz+Uky4CypYh7W55+RUabuIWybrPti3JJAazesHJXhefdnRTmd3nUWzpAI81pg5mEMGS42FyelfBOiXhTxaAJrsYH8ujmJc4rG88AK0jFdAP7J1HfJKC+fPvT44zyPnxrUuQ/f7rkPMOmX1uEliKzSnecHs0102Gmj0RFxkqjCZNgvAL/XX4Uy7+nbjCeQfKAG4AX7xIYm6gzcFb11CEeGPDFqEMHta+ocGmH8HYJ43K07fh0JaSfcqLrHeH/vZCib5cc8kddVqMVobOh9uFgpV8VUStozBPJL7z3nMiegI/P/QHzwEnKk5IHamyWJcMWRIodz6Fzh7ZC+JRsXITtKvvrxJ+tA=";

        let expected_shared = "T4KKTwQOEQ43G1UzPbBVzi219KXJ54qh6w24IMPEc0A=";

        let shared = {
            let sk_bytes = base64::decode(secret_key).unwrap();
            let secret_key = kyber768::SecretKey::from_bytes(&sk_bytes).unwrap();

            let ct_bytes = base64::decode(ciphertext).unwrap();
            let ciphertext = kyber768::Ciphertext::from_bytes(&ct_bytes).unwrap();

            let shared = kyber768::decapsulate(&ciphertext, &secret_key);

            base64::encode(shared.as_bytes())
        };

        assert_eq!(shared, expected_shared);
    }

    #[test]
    fn parse_get_response() {
        let testpkg = b"\x45\x00\x04\x64\x1E\x6E\x40\x00\x40\x11\x04\x0F\x0A\x05\x00\x01\x0A\x05\x00\x02\x19\x50\xF4\x47\x04\x50\xE0\x10\x01\x00\x00\x00\x40\x04\x00\x00\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";

        let cipher = super::parse_get_response(testpkg).unwrap();

        let expected = b"\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";
        assert_eq!(cipher.as_bytes(), expected);
    }

    #[test]
    fn parse_response_payload() {
        let testpkg = b"\x01\x00\x00\x00\x40\x04\x00\x00\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";

        let cipher = super::parse_response_payload(testpkg).unwrap();

        let expected = b"\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";
        assert_eq!(cipher.as_bytes(), expected);
    }
}
