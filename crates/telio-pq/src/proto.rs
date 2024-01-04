use std::{
    convert::TryInto,
    io::{self, Read},
    net::Ipv4Addr,
    ops::RangeInclusive,
};

use boringtun::noise;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::{prelude::Distribution, SeedableRng};
use tokio::net::{ToSocketAddrs, UdpSocket};

const SERVICE_PORT: u16 = 6480;
const LOCAL_PORT_RANGE: RangeInclusive<u16> = 49152..=u16::MAX; // dynamic port range
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 1);
const PQ_PROTO_VERSION: u32 = 1;
const CIPHERTEXT_LEN: u32 = kyber768::ciphertext_bytes() as _;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

struct TunnelSock {
    tunn: Box<noise::Tunn>,
    sock: telio_sockets::External<UdpSocket>,
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
) -> super::Result<super::Keys> {
    let TunnelSock { tunn, sock } = handshake(sock_pool, endpoint, secret, peers_pubkey).await?;

    let mut rng = rand::rngs::StdRng::from_entropy();

    // Generate keys
    let wg_secret = telio_crypto::SecretKey::gen_with(&mut rng);
    let (pq_public, pq_secret) = kyber768::keypair();
    let wg_public = telio_crypto::PublicKey::from(&wg_secret);

    // Send GET packet
    let pkgbuf = create_get_packet(&wg_public, &pq_public, &mut rng); // 4 KiB

    let mut recvbuf = [0u8; 2048]; // 2 KiB buffer should suffice
    match tunn.encapsulate(&pkgbuf, &mut recvbuf) {
        noise::TunnResult::Err(err) => {
            return Err(format!("Failed to encapsulate PQ keys message: {err:?}").into())
        }
        noise::TunnResult::WriteToNetwork(buf) => {
            sock.send(buf).await?;
        }
        _ => return Err("Unexpected WG tunnel output".into()),
    }

    // Receive response
    let read = sock.recv(&mut recvbuf).await?;

    let mut msgbuf = [0u8; 2048]; // 2 KiB buffer should shuffice

    #[allow(index_access_check)]
    let ciphertext = match tunn.decapsulate(None, &recvbuf[..read], &mut msgbuf) {
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

    Ok(super::Keys {
        pq_shared,
        wg_secret,
    })
}

async fn handshake(
    sock_pool: &telio_sockets::SocketPool,
    endpoint: impl ToSocketAddrs,
    secret: &telio_crypto::SecretKey,
    peers_pubkey: &telio_crypto::PublicKey,
) -> super::Result<TunnelSock> {
    let sock = sock_pool
        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
        .await?;
    sock.connect(endpoint).await?;

    let tunn = noise::Tunn::new(
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
            sock.send(buf).await?;
        }
        _ => return Err("Unexpected WG tunnel output".into()),
    }

    // The response should be 92, so the buffer is sufficient
    let read = sock.recv(&mut pkgbuf).await?;

    let mut msgbuf = [0u8; 2048];

    #[allow(index_access_check)]
    match tunn.decapsulate(None, &pkgbuf[..read], &mut msgbuf) {
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
    let mut cipherbuf = [0; CIPHERTEXT_LEN as usize];

    let ip = Ipv4Packet::new(pkgbuf).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys IP packet received",
    ))?;

    let udp = UdpPacket::new(ip.payload()).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys UDP packet received",
    ))?;

    let mut data = io::Cursor::new(udp.payload());

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

    data.read_exact(&mut cipherbuf)?;

    let ct = kyber768::Ciphertext::from_bytes(&cipherbuf)
        .map_err(|err| format!("Invalid PQ ciphertext received: {err:?}"))?;

    Ok(ct)
}

fn create_get_packet(
    wg_public: &telio_crypto::PublicKey,
    pq_public: &kyber768::PublicKey,
    rng: &mut impl rand::Rng,
) -> Vec<u8> {
    let mut pkgbuf = Vec::with_capacity(1024 * 4); // 4 KiB
    pkgbuf.resize(IPV4_HEADER_LEN + UDP_HEADER_LEN, 0);

    push_get_method_udp_payload(&mut pkgbuf, wg_public, pq_public);
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
///  WG pubkey len     , u32le, = 32
/// ---------------------------------
///  WG pubkey bytes   , [u8]
/// ---------------------------------
///  Kyber pubkey len  , u32le, = 1184
/// ---------------------------------
///  Kyber pubkey bytes, [u8]
/// ---------------------------------
fn push_get_method_udp_payload(
    pkgbuf: &mut Vec<u8>,
    wg_public: &telio_crypto::PublicKey,
    pq_public: &kyber768::PublicKey,
) {
    let method = 0u32; // get

    // UDP packet payload
    pkgbuf.extend_from_slice(&PQ_PROTO_VERSION.to_le_bytes());
    pkgbuf.extend_from_slice(&method.to_le_bytes());
    pkgbuf.extend_from_slice(&(wg_public.len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(wg_public);
    pkgbuf.extend_from_slice(&(pq_public.as_bytes().len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(pq_public.as_bytes());
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
        let secret_key = "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";
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
}
