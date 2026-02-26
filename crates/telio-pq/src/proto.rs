use std::{
    array::TryFromSliceError,
    io::{self, Read},
    net::Ipv4Addr,
    ops::RangeInclusive,
    time::SystemTime,
};

use blake2::Digest;
use hmac::Mac;
use neptun::noise;
use pnet_packet::{
    icmp::IcmpPacket,
    ip::{self, IpNextHeaderProtocols},
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};
use pqcrypto_kyber::{ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::{prelude::Distribution, rngs::OsRng};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn, Hidden};
use tokio::net::{ToSocketAddrs, UdpSocket};

const SERVICE_PORT: u16 = 6480;
const LOCAL_PORT_RANGE: RangeInclusive<u16> = 49152..=u16::MAX; // dynamic port range
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 1);
const CIPHERTEXT_LEN: u32 = kyber768::ciphertext_bytes() as _;
const REKEY_METHOD_ID: u32 = 1;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Eq, PartialEq)]
pub enum PqProtoV1Status {
    ServerError,
    DeviceError,
    PeerOrDeviceNotFound,
    CouldNotReadTimestamp,
    CouldNotReadVersion,
    CouldNotReadMessageType,
    Failure,
    UnhandledError,
    NoData,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PqProtoV2Status {
    ServerError,
    DeviceError,
    PeerOrDeviceNotFound,
    CouldNotReadTimestamp,
    CouldNotReadVersion,
    CouldNotReadMessageType,
    Failure,
    AuthenticationFailed,
    UnhandledError,
    NoData,
}

// Enums are copy-pasted from pq-upgrader
impl From<u8> for PqProtoV1Status {
    fn from(c: u8) -> Self {
        match c {
            1 => PqProtoV1Status::ServerError,
            2 => PqProtoV1Status::DeviceError,
            3 => PqProtoV1Status::PeerOrDeviceNotFound,
            4 => PqProtoV1Status::CouldNotReadTimestamp,
            5 => PqProtoV1Status::CouldNotReadVersion,
            6 => PqProtoV1Status::CouldNotReadMessageType,
            7 => PqProtoV1Status::Failure,
            _ => PqProtoV1Status::UnhandledError,
        }
    }
}

impl From<u8> for PqProtoV2Status {
    fn from(c: u8) -> Self {
        match c {
            1 => PqProtoV2Status::ServerError,
            2 => PqProtoV2Status::DeviceError,
            3 => PqProtoV2Status::PeerOrDeviceNotFound,
            4 => PqProtoV2Status::CouldNotReadTimestamp,
            5 => PqProtoV2Status::CouldNotReadVersion,
            6 => PqProtoV2Status::CouldNotReadMessageType,
            7 => PqProtoV2Status::Failure,
            8 => PqProtoV2Status::AuthenticationFailed,
            _ => PqProtoV2Status::UnhandledError,
        }
    }
}

struct TunnelSock {
    tunn: noise::Tunn,
    sock: telio_sockets::External<UdpSocket>,
}

pub struct KeySet {
    pub wg_keys: super::Keys,
    pub pq_secret: Hidden<[u8; PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES]>,
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
    pq_version: u32,
) -> super::Result<KeySet> {
    telio_log_debug!("Fetching keys");
    let TunnelSock { mut tunn, sock } =
        handshake(sock_pool, endpoint, secret, peers_pubkey).await?;
    telio_log_debug!("Initial WG handshake done");

    let mut rng = OsRng;

    // Generate keys
    let wg_secret = telio_crypto::SecretKey::gen_with(&mut rng);
    let (pq_public, pq_secret) = kyber768::keypair();
    let wg_public = wg_secret.public();

    let local_port = random_port(&mut rng);

    // Send GET packet
    let pkgbuf = create_get_packet(
        peers_pubkey,
        &wg_secret,
        &wg_public,
        &pq_public,
        local_port,
        pq_version,
    ); // 4 KiB

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

    let mut msgbuf = [0u8; 2048]; // 2 KiB buffer should suffice

    // Receive response
    let ciphertext = loop {
        let len = sock.recv(&mut recvbuf).await?;
        #[allow(clippy::indexing_slicing)]
        let pkg = &recvbuf[..len];

        telio_log_debug!("Received packet of size {}", pkg.len());

        match tunn.decapsulate(None, pkg, &mut msgbuf) {
            noise::TunnResult::Err(err) => {
                return Err(format!("Failed to decapsulate PQ keys message: {err:?}").into())
            }
            noise::TunnResult::WriteToTunnel(buf, _) => {
                match parse_get_response(buf, local_port, pq_version) {
                    Ok(cipehrtext) => break cipehrtext,
                    Err(err) => telio_log_warn!("Invalid PQ keys response: {err:?}"),
                }
            }
            _ => return Err("Unexpected WG tunnel output".into()),
        };
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
        pq_secret: Hidden(
            pq_secret
                .as_bytes()
                .try_into()
                .map_err(|e: TryFromSliceError| super::Error::Generic(e.to_string()))?,
        ),
    })
}

/// Authentication parameters required for PQ protocol version 2
pub struct RekeyV2Auth {
    pub pre_shared_key: telio_crypto::PresharedKey,
    pub wg_client_public: telio_crypto::PublicKey,
    pub wg_server_public: telio_crypto::PublicKey,
}

/// Establsh new PQ preshared key with the VPN server
pub async fn rekey(
    sock_pool: &telio_sockets::SocketPool,
    pq_secret: &Hidden<[u8; PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES]>,
    pq_version: u32,
    v2_auth: Option<RekeyV2Auth>,
) -> super::Result<telio_crypto::PresharedKey> {
    telio_log_debug!("Rekeying with version {}", pq_version);
    let mut pkgbuf = Vec::with_capacity(1024 * 4); // 4 KiB

    match pq_version {
        1 => push_rekey_method_udp_payload_v1(&mut pkgbuf),
        2 => {
            let auth = v2_auth.ok_or_else(|| {
                super::Error::Generic(
                    "Authentication parameters required for version 2".to_string(),
                )
            })?;

            push_rekey_method_udp_payload_v2(
                &mut pkgbuf,
                &auth.pre_shared_key,
                &auth.wg_client_public,
                &auth.wg_server_public,
            );
        }
        _ => {
            return Err(super::Error::Generic(format!(
                "Unsupported PQ version: {pq_version}",
            )))
        }
    }

    let sock = sock_pool
        .new_internal_udp((Ipv4Addr::UNSPECIFIED, 0), None)
        .await?;
    sock.connect((REMOTE_IP, SERVICE_PORT)).await?;

    telio_log_debug!("Sending rekey request");
    sock.send(&pkgbuf).await?;

    let mut recvbuf = [0u8; 2048];

    let len = sock.recv(&mut recvbuf).await?;
    #[allow(clippy::indexing_slicing)]
    let pkg = &recvbuf[..len];

    telio_log_debug!("Received packet of size {}", pkg.len());

    #[allow(clippy::indexing_slicing)]
    let ciphertext = parse_response_payload(pkg, pq_version)?;

    // Extract the shared secret
    let pq_shared = kyber768::decapsulate(
        &ciphertext,
        &SecretKey::from_bytes(&**pq_secret).map_err(|e| super::Error::Generic(e.to_string()))?,
    );
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
    let sock = sock_pool
        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
        .await?;
    sock.connect(endpoint).await?;

    let mut tunn = noise::Tunn::new(
        secret.clone().into_bytes().into(),
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
    let len = sock.recv(&mut pkgbuf).await?;
    #[allow(clippy::indexing_slicing)]
    let pkg = &pkgbuf[..len];

    telio_log_debug!("Handshake response received");

    let mut msgbuf = [0u8; 2048];

    #[allow(clippy::indexing_slicing)]
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

pub fn parse_get_response(
    pkgbuf: &[u8],
    local_port: u16,
    expected_version: u32,
) -> super::Result<kyber768::Ciphertext> {
    let ip = Ipv4Packet::new(pkgbuf).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys IP packet received",
    ))?;

    validate_get_response_ip(&ip).map_err(|reason| {
        io::Error::new(io::ErrorKind::InvalidData, format!("PQ keys IP: {reason}"))
    })?;

    let udp = UdpPacket::new(ip.payload()).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PQ keys UDP packet received",
    ))?;

    validate_get_response_udp(&udp, local_port, ip.get_source(), ip.get_destination()).map_err(
        |reason| io::Error::new(io::ErrorKind::InvalidData, format!("PQ keys UDP: {reason}")),
    )?;

    parse_response_payload(udp.payload(), expected_version)
}

fn validate_get_response_ip(ip: &Ipv4Packet) -> Result<(), String> {
    if ip.get_source() != REMOTE_IP {
        return Err("invalid src IP".to_owned());
    }
    if ip.get_destination() != LOCAL_IP {
        return Err("invalid dst IP".to_owned());
    }
    let next_level_protocol = ip.get_next_level_protocol();
    if next_level_protocol != ip::IpNextHeaderProtocols::Udp {
        if next_level_protocol == ip::IpNextHeaderProtocols::Icmp {
            if let Some(packet) = IcmpPacket::new(ip.payload()) {
                return Err(format!("invalid protocol, icmp: {packet:?}"));
            }
        }
        return Err("invalid protocol".to_owned());
    }
    if ip.get_checksum() != ipv4::checksum(ip) {
        return Err("checksum mismatch".to_owned());
    }

    Ok(())
}

fn validate_get_response_udp(
    udp: &UdpPacket,
    local_port: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<(), &'static str> {
    if udp.get_source() != SERVICE_PORT {
        return Err("invalid src port");
    }
    if udp.get_destination() != local_port {
        return Err("invalid dst port");
    }
    if udp.get_checksum() != udp::ipv4_checksum(udp, &src_ip, &dst_ip) {
        return Err("checksum mismatch");
    }

    Ok(())
}

/// The response looks as follows:
///
/// V1 format:
/// ---------------------------------
///  version           , u32le, = 1
/// ---------------------------------
///  Ciphertext len    , u32le, = 1088
/// ---------------------------------
///  Ciphertext bytes  , [u8]
/// ---------------------------------
///
/// V2 format:
/// ---------------------------------
///  version           , u32le, = 2
/// ---------------------------------
///  method            , u32le, = 0 (GetKey) or 1 (ReKey)
/// ---------------------------------
///  Ciphertext len    , u32le, = 1088
/// ---------------------------------
///  Ciphertext bytes  , [u8]
/// ---------------------------------
pub fn parse_response_payload(
    payload: &[u8],
    expected_version: u32,
) -> super::Result<kyber768::Ciphertext> {
    let mut data = io::Cursor::new(payload);

    let mut version = [0u8; 4];
    data.read_exact(&mut version)?;
    let version = u32::from_le_bytes(version);
    if version != expected_version {
        return Err(super::Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server responded with invalid PQ handshake version",
        )));
    }

    match expected_version {
        1 => {
            // v1 reports error as a single(5th) byte with no further payload.
            #[allow(clippy::comparison_chain)]
            if payload.len() < 5 {
                return Err(super::Error::ServerV1(PqProtoV1Status::NoData));
            } else if payload.len() == 5 {
                #[allow(clippy::indexing_slicing)]
                let error_code = payload[4];
                let status = PqProtoV1Status::from(error_code);
                telio_log_error!(
                    "PQ upgrader v1 responded with: {}: {:?}",
                    error_code,
                    status
                );
                return Err(super::Error::ServerV1(status));
            }
        }
        2 => {
            // v2 format includes a method field and reports errors as:
            // version: u32 || method: u32 (= 2 for error) || code: u32
            // Total error response size is 12 bytes.
            // See LLT RFC-0102 for details.
            if payload.len() < 12 {
                return Err(super::Error::ServerV2(PqProtoV2Status::NoData));
            }

            // Read method field
            let mut method = [0u8; 4];
            data.read_exact(&mut method)?;
            let method = u32::from_le_bytes(method);

            // Method 2 indicates an error response
            const MESSAGE_TYPE_ERROR: u32 = 2;
            if method == MESSAGE_TYPE_ERROR {
                let mut error_code = [0u8; 4];
                data.read_exact(&mut error_code)?;
                let error_code = u32::from_le_bytes(error_code) as u8;
                let status = PqProtoV2Status::from(error_code);
                telio_log_error!(
                    "PQ upgrader v2 responded with: {}: {:?}",
                    error_code,
                    status
                );
                return Err(super::Error::ServerV2(status));
            }
        }
        _ => {
            return Err(super::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported PQ version: {expected_version}"),
            )));
        }
    }

    let mut ciphertext_len = [0u8; 4];
    data.read_exact(&mut ciphertext_len)?;
    let ciphertext_len = u32::from_le_bytes(ciphertext_len);

    if ciphertext_len != CIPHERTEXT_LEN {
        return Err(super::Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server responded with invalid PQ handshake ciphertext length",
        )));
    }

    let mut cipherbuf = [0; CIPHERTEXT_LEN as usize];
    data.read_exact(&mut cipherbuf)?;

    let ct = kyber768::Ciphertext::from_bytes(&cipherbuf).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PQ ciphertext received: {err:?}"),
        )
    })?;

    Ok(ct)
}

fn create_get_packet(
    wg_server_public: &telio_crypto::PublicKey,
    wg_client_secret: &telio_crypto::SecretKey,
    wg_client_public: &telio_crypto::PublicKey,
    pq_public: &kyber768::PublicKey,
    local_port: u16,
    pq_version: u32,
) -> Vec<u8> {
    let mut pkgbuf = Vec::with_capacity(1024 * 4); // 4 KiB
    pkgbuf.resize(IPV4_HEADER_LEN + UDP_HEADER_LEN, 0);

    push_get_method_udp_payload_without_auth_tag(
        &mut pkgbuf,
        wg_client_public,
        pq_public,
        pq_version,
    );

    #[allow(clippy::indexing_slicing)]
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

    fill_get_packet_headers(pkgbuf.as_mut_slice(), local_port);

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
    pq_version: u32,
) {
    let method = 0u32; // get
    let timestamp = timestamp();

    // UDP packet payload
    pkgbuf.extend_from_slice(&pq_version.to_le_bytes());
    pkgbuf.extend_from_slice(&method.to_le_bytes());
    pkgbuf.extend_from_slice(&timestamp.to_le_bytes());
    pkgbuf.extend_from_slice(&(wg_public.len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(wg_public);
    pkgbuf.extend_from_slice(&(pq_public.as_bytes().len() as u32).to_le_bytes());
    pkgbuf.extend_from_slice(pq_public.as_bytes());
}

/// Derive authentication key for PQ protocol version 2
/// key = derive_key(context: "pq-auth", key_material: pre-shared-key || wg_public_key_client || wg_public_key_server)
fn derive_pq_auth_key(
    pre_shared_key: &telio_crypto::PresharedKey,
    wg_client_public: &telio_crypto::PublicKey,
    wg_server_public: &telio_crypto::PublicKey,
) -> [u8; 32] {
    let mut key_material = [0u8; 32 + 32 + 32];
    #[allow(clippy::indexing_slicing)]
    {
        key_material[0..32].copy_from_slice(pre_shared_key);
        key_material[32..64].copy_from_slice(wg_client_public);
        key_material[64..96].copy_from_slice(wg_server_public);
    }

    blake3::derive_key("pq-auth", &key_material)
}

/// The REKEY payload (v1) looks as follows:
///
/// --------------------------------
///  version           , u32le, = 1
/// --------------------------------
///  method            , u32le, = 1
/// ---------------------------------
fn push_rekey_method_udp_payload_v1(pkgbuf: &mut Vec<u8>) {
    let version = 1u32;

    // UDP packet payload
    pkgbuf.extend_from_slice(&version.to_le_bytes());
    pkgbuf.extend_from_slice(&REKEY_METHOD_ID.to_le_bytes());
}

/// The REKEY payload (v2) looks as follows:
///
/// --------------------------------
///  version           , u32le, = 2
/// --------------------------------
///  method            , u32le, = 1
/// --------------------------------
///  timestamp         , u64le
/// --------------------------------
///  auth_tag          , [u8; 32]
/// ---------------------------------
fn push_rekey_method_udp_payload_v2_with_timestamp(
    pkgbuf: &mut Vec<u8>,
    pre_shared_key: &telio_crypto::PresharedKey,
    wg_client_public: &telio_crypto::PublicKey,
    wg_server_public: &telio_crypto::PublicKey,
    timestamp: u64,
) {
    let version = 2u32;

    // UDP packet payload
    pkgbuf.extend_from_slice(&version.to_le_bytes());
    pkgbuf.extend_from_slice(&REKEY_METHOD_ID.to_le_bytes());
    pkgbuf.extend_from_slice(&timestamp.to_le_bytes());

    // Derive authentication key
    let auth_key = derive_pq_auth_key(pre_shared_key, wg_client_public, wg_server_public);

    // Generate authentication tag
    let auth_tag: [u8; 32] = blake3::keyed_hash(&auth_key, pkgbuf).into();
    pkgbuf.extend_from_slice(&auth_tag);
}

fn push_rekey_method_udp_payload_v2(
    pkgbuf: &mut Vec<u8>,
    pre_shared_key: &telio_crypto::PresharedKey,
    wg_client_public: &telio_crypto::PublicKey,
    wg_server_public: &telio_crypto::PublicKey,
) {
    push_rekey_method_udp_payload_v2_with_timestamp(
        pkgbuf,
        pre_shared_key,
        wg_client_public,
        wg_server_public,
        timestamp(),
    );
}

/// Sets up UDP and IP headers in the provided buffer
///
/// # Panics
///
/// Panics if the buffer size is less than IP + UDP headers bytes.
fn fill_get_packet_headers(pkgbuf: &mut [u8], local_port: u16) {
    let pkg_len = pkgbuf.len();

    #[allow(clippy::expect_used)]
    #[allow(clippy::indexing_slicing)]
    let mut udppkg = MutableUdpPacket::new(&mut pkgbuf[IPV4_HEADER_LEN..])
        .expect("UDP buffer should not be too small");
    udppkg.set_source(local_port);
    udppkg.set_destination(SERVICE_PORT);
    udppkg.set_length((pkg_len - IPV4_HEADER_LEN) as _);
    udppkg.set_checksum(udp::ipv4_checksum(
        &udppkg.to_immutable(),
        &LOCAL_IP,
        &REMOTE_IP,
    ));
    drop(udppkg);

    #[allow(clippy::expect_used)]
    #[allow(clippy::indexing_slicing)]
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

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use core::time;

    use crate::{
        proto::{PqProtoV1Status, PqProtoV2Status},
        Error,
    };
    use base64::prelude::*;
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::{Ciphertext, SecretKey as _, SharedSecret};

    #[test]
    // The Kyber KEM has two competing algorithms and the library we're using changed the algorithm in their new version.
    // The test here is for capturing the eventual regression when the library is updated for example.
    fn decapsulate_kyber_ciphertext() {
        let secret_key = "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";
        let ciphertext = "1PXYvRAU31rbjedEJLRVRiNVShRNt9RrBar0hzN4iqBQuSBYyVwZy4FwMHRQz5cnljn5gsQlUP3+jhkYL5YQqNy//oJtBwCz2NWzjXu2BzphKJaGE9FbBmvpwhTa70BdYbCri11GOK+bO6dpTTFaF0NqMhdDlMuvD9yv93RzTNfoZtVuqjTGvitx2bY+aCshir8mZ9iox3kyxcf8OIR7mFjUNQgRPgmvdmYSHqFuvaOSWQjxlzdkG0V3zlUr7IUusGLYFDSMqHPqMbm2HTWcaF7UsF/NwrUcUsm2mxev7QBu7nIBWQzMmnWacH6/0cxj/AOfv8TsdK6QUYrSYUFTHVWkbXwodpG4/5kzt6z4BhqS7d3Z30Pg4K+PA/5yQseGpgADOZlHfoqEysdDZ7Y+dypaXVX2Z6kUokwIcxKglJQYUTezGwUztukiTSVoTJ2osTJ5LnU3quuP/NZmdKdsuUs0fBaPTQ7gl2gaxc3LhXjmOPvU8VNZf0hJNlA91h6RCgCbn0z634I8LmCr94TZa1GJcIy7JvKZC2g9XhoIdjSuDuzjH0T7qixqZwib+wGzUJ5Mcz+SIMCwpSIALxsyOfuB5/E2eLnbtt1TWwMCq1O6HSgjDD2dT0qV3AQ9ZKkbggfjG53npNfK82zufBPhWphTly6Fv9yCWguXH/9pK46MnBUVWeiB1RQFl9/R/oflkg5Mlqe07lmBNWotYlg14IVG+ZF69jKtp6dIBe2bWzvH4SYn/2bhpwGGWZUQ1ZkoZvY6dUqglhnTzmBgXdXLSVDueVklXg1saHIFWYug/Friy+U5mU6AxYs1uEqfdf7x1GWbHjyHsaDG1WSGx2xHQ+5nvGsM7a9LR83BMtiFgJe9cWxPvYdD16FZEbax9uu1kgY+3ESgjJXY5uTD7igx0SuR+Q6DBc+7GwFY7Ox9U1FHUg2+mAV4QTh/gsA1d2FXkORbs/1GUMP8cjkmOyIVaNegPYPgsF22UyNbE3h25biTY+XbP3x9E2fCDGGB4XTG8muwBljndoiBuyp0xyCZ1IGl3siS13RXCJbkY7hFLVyOWExHZB2hQ6TX6a7wLP88YtbKcJK9viyixWz+Uky4CypYh7W55+RUabuIWybrPti3JJAazesHJXhefdnRTmd3nUWzpAI81pg5mEMGS42FyelfBOiXhTxaAJrsYH8ujmJc4rG88AK0jFdAP7J1HfJKC+fPvT44zyPnxrUuQ/f7rkPMOmX1uEliKzSnecHs0102Gmj0RFxkqjCZNgvAL/XX4Uy7+nbjCeQfKAG4AX7xIYm6gzcFb11CEeGPDFqEMHta+ocGmH8HYJ43K07fh0JaSfcqLrHeH/vZCib5cc8kddVqMVobOh9uFgpV8VUStozBPJL7z3nMiegI/P/QHzwEnKk5IHamyWJcMWRIodz6Fzh7ZC+JRsXITtKvvrxJ+tA=";

        let expected_shared = "T4KKTwQOEQ43G1UzPbBVzi219KXJ54qh6w24IMPEc0A=";

        let shared = {
            let sk_bytes = BASE64_STANDARD.decode(secret_key).unwrap();
            let secret_key = kyber768::SecretKey::from_bytes(&sk_bytes).unwrap();

            let ct_bytes = BASE64_STANDARD.decode(ciphertext).unwrap();
            let ciphertext = kyber768::Ciphertext::from_bytes(&ct_bytes).unwrap();

            let shared = kyber768::decapsulate(&ciphertext, &secret_key);

            BASE64_STANDARD.encode(shared.as_bytes())
        };

        assert_eq!(shared, expected_shared);
    }

    #[test]
    fn parse_get_response() {
        let testpkg = b"\x45\x00\x04\x64\x1E\x6E\x40\x00\x40\x11\x04\x0F\x0A\x05\x00\x01\x0A\x05\x00\x02\x19\x50\xF4\x47\x04\x50\xE0\x10\x01\x00\x00\x00\x40\x04\x00\x00\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";
        let cipher = super::parse_get_response(testpkg, 62535, 1).unwrap();

        let expected = b"\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";
        assert_eq!(cipher.as_bytes(), expected);
    }

    #[test]
    fn parse_get_response_invalid() {
        let testpkg = b"E\x00\x00\xb0\xbc2@\x00@\x11\x97\xc3\xc0\xa82\x01\xc0\xa82\xf5";
        assert!(super::parse_get_response(testpkg, 62535, 1).is_err());
    }

    #[test]
    fn parse_get_response_with_intvalid_icmp() {
        let input = vec![
            0x45, 0xc0, 0x2, 0x40, 0xd7, 0xe5, 0x0, 0x0, 0x40, 0x1, 0x8c, 0xb, 0xa, 0x5, 0x0, 0x1,
            0xa, 0x5, 0x0, 0x2, 0x3, 0x3, 0xa0, 0xfa, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x5, 0x14,
            0x0, 0x0, 0x40, 0x0, 0xff, 0x11, 0x62, 0xcc, 0xa, 0x5, 0x0, 0x2, 0xa, 0x5, 0x0, 0x1,
            0xe4, 0xe4, 0x19, 0x50, 0x5, 0x0, 0x5b, 0xe1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xc4, 0x32, 0xaf, 0x67, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x38, 0xad, 0xfc,
            0x1b, 0x88, 0xe2, 0x72, 0xe, 0x9b, 0x43, 0x1b, 0x4f, 0x51, 0x51, 0x80, 0xac, 0x23,
            0x51, 0x3a, 0x86, 0xaa, 0x53, 0xfb, 0x81, 0x7b, 0xe7, 0x16, 0xca, 0xf3, 0xcc, 0x3e,
            0x41, 0xa0, 0x4, 0x0, 0x0, 0xf0, 0x93, 0x7b, 0x43, 0x65, 0xbf, 0x5a, 0x7b, 0x5b, 0x19,
            0xca, 0xc1, 0xd, 0xa, 0x8b, 0xb8, 0x44, 0x5, 0xf6, 0x70, 0x49, 0x2e, 0xdc, 0x57, 0x5d,
            0x63, 0x24, 0x5, 0xf9, 0xa2, 0x5e, 0xc6, 0x59, 0x95, 0xa9, 0x6d, 0xd7, 0x6c, 0x18,
            0xdd, 0xfa, 0x40, 0x83, 0xb6, 0x87, 0xd6, 0x8c, 0x25, 0x11, 0x16, 0x8e, 0x6d, 0x8b,
            0x78, 0x68, 0xd1, 0x76, 0xdf, 0x7a, 0x36, 0xdf, 0xea, 0x3a, 0x83, 0xf1, 0x66, 0x19,
            0x22, 0x14, 0x1e, 0x30, 0x35, 0x49, 0x73, 0x4f, 0x4c, 0x63, 0x74, 0xd7, 0x32, 0xac,
            0x92, 0x57, 0xa0, 0x2c, 0x1, 0x53, 0xd5, 0xa, 0xcb, 0x41, 0x50, 0xe, 0x6e, 0x96, 0x74,
            0x85, 0xba, 0x51, 0x26, 0x64, 0x6b, 0xe3, 0x69, 0x5, 0x98, 0x43, 0x9, 0x69, 0x68, 0xc3,
            0x31, 0xf4, 0x35, 0x4f, 0x85, 0xa3, 0xb2, 0x88, 0xa1, 0xd9, 0xb9, 0xa2, 0xee, 0x48,
            0xb6, 0x69, 0xa5, 0x43, 0x83, 0xfc, 0x61, 0x18, 0x4b, 0x10, 0x7d, 0x60, 0x6b, 0xee,
            0x92, 0xbe, 0x80, 0xca, 0xa6, 0x3c, 0xe7, 0x53, 0x40, 0xba, 0x1c, 0x1a, 0xa7, 0x7a,
            0x6c, 0x15, 0x0, 0xaa, 0x92, 0x48, 0x44, 0x49, 0x53, 0x12, 0xcc, 0xa3, 0x56, 0x3b,
            0x28, 0xf0, 0x7c, 0x9, 0xf1, 0xac, 0x73, 0xc6, 0x2, 0x49, 0xec, 0x91, 0x40, 0x5a, 0xc0,
            0x48, 0x4a, 0xb5, 0xc4, 0x8e, 0xdc, 0x92, 0x1, 0x36, 0x16, 0x5f, 0x99, 0x4f, 0x63,
            0x8c, 0x15, 0x7e, 0xda, 0x25, 0x8e, 0x49, 0x53, 0x38, 0x16, 0x99, 0xed, 0xea, 0x22,
            0x73, 0x40, 0xc1, 0xc2, 0xa1, 0x9c, 0x77, 0x6a, 0x19, 0xf3, 0xf4, 0x6e, 0xd6, 0x9c,
            0x15, 0xf1, 0x3b, 0x7b, 0xed, 0x3c, 0x94, 0x59, 0x0, 0x55, 0xcd, 0x4, 0x6a, 0xd2, 0x6b,
            0x35, 0x61, 0x58, 0xac, 0x9c, 0x13, 0xc2, 0xf, 0x22, 0xa1, 0x16, 0x15, 0x33, 0x7e,
            0xa3, 0x47, 0x2a, 0xd8, 0x15, 0xe7, 0x29, 0xc2, 0x27, 0xc9, 0x6, 0xd9, 0xb6, 0x35,
            0x39, 0x18, 0x1a, 0x47, 0xa7, 0x57, 0xd9, 0xec, 0xb9, 0xd9, 0xc5, 0x8b, 0x4e, 0xf4,
            0x17, 0x8a, 0xda, 0x5, 0x82, 0xb, 0x71, 0x4d, 0x26, 0x84, 0x54, 0x39, 0x3, 0x9c, 0x45,
            0x1f, 0x75, 0x65, 0x45, 0x7a, 0x57, 0xa1, 0x8b, 0xa0, 0x22, 0xbc, 0x61, 0x36, 0xe0,
            0x4b, 0x3e, 0x70, 0xd4, 0x7f, 0xf6, 0xe4, 0x7a, 0xa9, 0xd3, 0x8e, 0xa3, 0x5a, 0x7e,
            0x4c, 0xf9, 0xbd, 0x2e, 0x79, 0xbd, 0x64, 0xc2, 0x30, 0xb4, 0x27, 0x22, 0xef, 0x30,
            0xa, 0xfc, 0xa6, 0xbc, 0x36, 0xa7, 0x2f, 0xa2, 0x83, 0xb5, 0x12, 0x78, 0x5c, 0x82,
            0x27, 0x2d, 0xa7, 0xc2, 0x38, 0xc9, 0xe5, 0xb3, 0xc, 0x8b, 0x74, 0x2d, 0x37, 0xae,
            0xc7, 0x61, 0x6f, 0xbb, 0x85, 0x38, 0x89, 0x3a, 0x7d, 0x81, 0xfb, 0x9, 0x5b, 0x7c,
            0x3c, 0x1d, 0x6, 0x25, 0xcf, 0x80, 0xce, 0x45, 0xe0, 0x8b, 0x16, 0x90, 0x2b, 0x39,
            0x95, 0x8, 0x66, 0x50, 0x6e, 0x1b, 0xd8, 0x7f, 0x10, 0x56, 0x35, 0x61, 0x25, 0x5e,
            0xb1, 0xf5, 0xb4, 0x9f, 0x32, 0x63, 0x39, 0x8, 0x86, 0x11, 0xcc, 0x39, 0x98, 0x74,
            0x27, 0x9d, 0x6c, 0x6c, 0x3b, 0xd5, 0xcd, 0xb3, 0x8c, 0x90, 0xdb, 0xf4, 0xb2, 0xd9,
            0x1c, 0x49, 0x40, 0x35, 0x6d, 0x48, 0x76, 0x2e, 0x14, 0xf7, 0x68, 0xd3, 0x38, 0x10,
            0x79, 0x42, 0x73, 0x3, 0xc7, 0x1e, 0x37, 0x96, 0x7c, 0x5d, 0x93, 0x95, 0x26, 0x71,
        ];
        let result = super::parse_get_response(&input, 0, 0);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                format!("{e:?}").contains(
                "IcmpPacket { icmp_type : IcmpType(3), icmp_code : IcmpCode(3), checksum : 41210,  }"
            ));
        }
    }

    #[test]
    fn parse_response_payload() {
        let testpkg = b"\x01\x00\x00\x00\x40\x04\x00\x00\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";

        let cipher = super::parse_response_payload(testpkg, 1).unwrap();

        let expected = b"\x67\xA6\x9C\x16\x98\xFF\x14\x9E\xEF\xBA\xDE\x97\x4F\x08\x42\x23\xCD\x4B\xD3\x35\xBE\x77\x80\x65\x31\x57\x4F\x28\x8E\x44\x8E\x8D\xB8\xA5\xB5\xDF\x02\x53\x33\x53\x2A\xDC\x84\x83\x01\x67\x6B\x66\xAD\x44\xAE\x77\x33\xA1\x0A\x92\x8A\xDA\xF1\xAD\x1B\xFF\x39\xB0\xCA\x28\x0C\xA7\x05\xD7\xCF\x8A\x57\xD2\x08\x2F\x4C\xA7\xB7\xF3\x9B\xEE\x0D\xA5\x09\x5B\xF9\xB3\x35\x95\x35\x07\x9D\x83\xE5\xE0\x3C\x9D\x77\xB9\xF7\x96\xF3\x76\x93\x43\x61\x67\xD3\xED\x61\x39\xB8\x71\xEA\x54\xD2\xFD\xCE\xDE\x98\xFF\x7A\x05\x01\x57\x35\xB0\x47\x3A\xC9\x67\x52\x51\xAD\xE2\x6A\x2A\x2E\x80\xD6\xBB\x25\x5E\x69\xAC\x34\x65\xFF\xC4\xD4\x09\x35\x0B\x09\xD3\x4B\xCE\xC2\x40\xAD\xD8\xDF\x9F\x34\x20\x9A\xA6\xEC\xCF\x81\x52\xBD\xE6\x5C\xBD\xE9\x8C\xD6\xD4\xAD\x5D\x5A\x57\xB4\x64\x61\x9E\x51\xC7\x6D\xE7\x4D\x6A\xBF\x23\x71\x9D\xEB\x42\x4E\xF7\x8D\xD6\x84\x31\xED\x3F\x15\x70\xAB\xA5\xA9\x0D\x80\x80\xAA\xA3\xA8\x7E\x17\x4B\x99\x8B\xA9\x39\xB5\x2E\x61\x67\xE1\xCD\x59\xD8\x0D\x21\xA5\xFA\x5E\xF1\x9C\x34\x67\x44\xB8\x2B\xDB\xD8\x19\x8B\xE2\x15\xA2\x30\x5E\x0D\x6A\xD4\x45\x5A\xF4\x0C\x91\x55\x4D\xFA\xB6\xDB\xDD\x69\xE2\x96\x75\xEE\xA0\x32\x4E\x5D\x39\xA9\x27\xF6\x64\xF1\x98\x05\x39\x71\x0F\x3E\x3B\x4E\x19\x0C\x21\x4B\x39\xC5\xAC\x8C\xC1\xF6\xE3\x6D\x13\x66\xDF\x35\xD9\x0E\xB0\x8D\x81\x94\xD6\x0B\xCA\x3C\x3A\xF2\x66\xF4\xF7\x40\xFE\x59\x39\x26\x44\x75\x7D\x4A\xAD\xEE\x4E\x8C\xD8\xB4\xCB\xFE\xEA\xE9\xA4\x5A\x9C\x6C\x3F\x0E\xE1\xCD\x64\x7E\xDA\x47\x4E\x07\xCC\x78\x2F\x50\x6F\x5B\x52\x22\x29\x23\x5A\xEA\x2D\xEB\x3F\x9E\xEC\x15\xDE\x1F\x44\x5C\x16\x95\xC0\x1F\xA2\x90\x5F\xA3\x31\x8F\xFE\x4A\x31\xA8\x34\xBC\x3A\xF9\x1D\x7F\x34\x02\xDF\xD7\xD3\x4F\x96\x73\x73\x18\x16\x9C\x87\x97\xD4\xCE\x63\xC2\x83\x90\x2D\xC8\xDF\x6A\xAB\xFD\x81\x74\x8F\xDF\x09\x6D\xA3\xCD\xB7\x50\xE1\x88\xA6\x75\xCD\x8B\x55\x75\xD2\x26\x49\xC4\x6E\x9A\x2B\xA5\x13\xDB\x8F\xC7\x9E\xE9\x6E\xE2\xEE\x9F\x1E\xAF\x77\xF8\x89\x17\xF2\xD5\xF7\x89\x3F\xC3\x18\x16\x86\x57\x1F\x9F\xD0\xF1\xC3\xCC\x45\x67\xA2\x45\x6A\x16\x6B\x2B\xF5\xAA\x56\x6E\x80\xC0\x91\x1D\x2B\x0A\xCB\xCF\x1F\x80\x20\x18\x71\x6B\x6E\x46\x5C\x05\xE4\x73\x7E\xB4\x2B\x98\x40\x23\xC8\x6C\xA4\xCB\xD6\x12\xF6\xF4\xCB\x06\x75\xBC\x6B\xDC\x44\x71\xBB\x11\x69\x97\x8B\xD2\x15\xAD\x98\xBB\xCD\xA2\x5A\x77\x3D\xFC\xC3\x43\x79\xC8\xF9\x33\x87\x22\x9E\x20\x02\x63\x23\x48\xDD\xC7\x45\x44\x06\x10\x16\x4C\x35\x26\xB0\xAC\x5C\x98\x24\x9D\xC2\x1A\x48\x48\x49\x0F\x93\xE8\x6E\xE7\xB3\x77\xD2\xE5\x64\xDD\x49\x1C\x87\x77\x98\x11\xF6\xD0\x0C\xEB\x95\x73\x46\x51\x9F\xFC\x10\x23\x19\xD3\x73\x08\xFA\xFF\xCF\x70\x5C\x03\x34\x53\xC9\x65\x76\x00\xB9\x7C\x1C\x30\x1A\x9E\x0E\xD6\x2B\x8F\xB5\xC9\x50\xDA\x4B\x37\xF2\xC2\x86\x07\xB4\xE1\x70\x42\x1A\xAB\x70\x9F\x06\x72\xED\xBF\x45\x1D\xEA\x3E\x6C\xCF\xC6\x74\x0C\xA8\x9B\xAB\xCF\xEC\x62\xA9\xAB\x70\xF9\x1C\xA0\xBF\x99\x86\x3D\x1F\xE0\xA9\xCC\x9A\x6E\xD2\x8B\xB4\xBB\x29\xFA\xC3\x7D\xAC\xF9\x3C\x44\x06\xC8\xB2\x49\x3F\x26\x86\xA7\x8B\x13\x8E\x3A\xDF\x73\xEC\x94\xAE\xA2\x0C\x4C\x19\x13\x85\xED\x50\xF3\xCA\x53\xA5\x8E\x9F\xC6\x00\x44\xD8\x73\x08\x2C\xA0\x4D\x7A\xB0\xF7\xE5\x25\xD0\x22\x78\x47\x08\xB1\x55\x01\x98\x5A\xCE\xB8\x6B\x4B\x2F\x0B\x83\x54\x83\x70\xC8\xEB\xCE\x41\xA7\xBF\x33\x9A\x58\xDA\x36\x79\x56\xFD\x88\x30\x94\x31\x48\xF5\x9E\xA6\x2D\xEA\x05\x03\x27\x9E\x76\x72\xA6\xC8\x45\xFD\xEF\xB4\xCB\xBF\xC5\xC3\x02\x13\x33\x37\x02\xD8\x8A\x3C\x8A\x46\xC3\x3C\xBA\x0A\xEB\x9D\x46\x81\xF2\x97\xD5\x38\xFD\xC8\xF4\x6A\x7B\x56\x23\xED\x70\xA6\x58\x40\x61\x0A\x3C\x48\xE3\x01\xE4\x32\xFA\xC5\xE9\x80\xAB\x1B\x37\x04\x45\x0D\x10\x6E\x54\x18\xDE\xAA\x4E\xF0\x0A\x56\x45\xA4\x27\xE2\xC2\xA3\x0D\xB4\x57\xDE\xD0\x08\xE5\xE0\xBE\xF8\xC9\x8F\x1D\x09\x2D\x18\x83\xB4\xBD\x64\xD2\x52\x6C\x16\x81\x7C\x6F\x0F\x04\x62\x6D\x38\xFF\x11\xA1\xED\x86\xF2\xB0\xE1\x72\x33\xF0\x99\xBD\xC5\xA6\x00\xF5\x2C\x3D\x73\xFE\xE8\xBB\x75\xF5\xF5\x5C\x8D\x71\xE8\x90\xF7\x5D\xFE\x3B\x6D\xD3\xCE\x02\x6E\x4F\x07\x6E\x89\xBD\x62\x15\xCB\xB5\xFE\x8E\xCE\x28\x34\xFC\xA0\xC5\xFE\x4A\x8C\x6E\xFE\x8C\xE0\x5B\x3B\x72\x9F\x26\x46\xA3\x62\x36\x4B\xDA\x1F\xB1\xC6\xC2\x31\x4B\xB6\x5A\x95\xF9\x5F\x74\x38\x65\x42\xF5\x6D\xB8\x9B\xFB\x95\xDA\xCE\xEB\x47\xC8\x00\xFC\x15\x29\x23\x1A\xD0\xD7\x84\x4F\xBA\x0F\x03\xBE\x78\x51\x03\x8E\x89\xA5\xBF\xD0\x26\x75\xA5\x27\x2F\x97\x98\x01\x68\x33\x88\x4A\x62\x8B\x49\x8E\x18\x33\xA9\x0C\x5C\x07\x0D\x9C\xAC\x11\xD9\x39\x60\xAA\xD8\x28\x64\x19\xE6\xDE\x61\xEC\xC4\x0B\x72\x21\xED\xAA\x54\xDD\xC8\xE6\x0F\x0C\x51\x8D\xF7";
        assert_eq!(cipher.as_bytes(), expected);
    }

    #[test]
    fn parse_response_error_v1() {
        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x01", 1),
            Err(Error::ServerV1(PqProtoV1Status::ServerError))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x02", 1),
            Err(Error::ServerV1(PqProtoV1Status::DeviceError))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x03", 1),
            Err(Error::ServerV1(PqProtoV1Status::PeerOrDeviceNotFound))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x04", 1),
            Err(Error::ServerV1(PqProtoV1Status::CouldNotReadTimestamp))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x05", 1),
            Err(Error::ServerV1(PqProtoV1Status::CouldNotReadVersion))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x06", 1),
            Err(Error::ServerV1(PqProtoV1Status::CouldNotReadMessageType))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x07", 1),
            Err(Error::ServerV1(PqProtoV1Status::Failure))
        ));

        // Pass unknown errors
        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x10", 1),
            Err(Error::ServerV1(PqProtoV1Status::UnhandledError))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00\x20", 1),
            Err(Error::ServerV1(PqProtoV1Status::UnhandledError))
        ));

        assert!(matches!(
            super::parse_response_payload(b"\x01\x00\x00\x00", 1),
            Err(Error::ServerV1(PqProtoV1Status::NoData))
        ));

        // Pass another version and don't expect v1 status codes
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02", 1),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x01", 1),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x40", 1),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn test_push_rekey_method_udp_payload_v2() {
        let pre_shared_key = telio_crypto::PresharedKey::new([1u8; 32]);
        let wg_client_public = telio_crypto::PublicKey::from(&[2u8; 32]);
        let wg_server_public = telio_crypto::PublicKey::from(&[3u8; 32]);
        let timestamp = 0x11_22_33_44_55_66_77_88;

        let mut pkgbuf = Vec::new();
        super::push_rekey_method_udp_payload_v2_with_timestamp(
            &mut pkgbuf,
            &pre_shared_key,
            &wg_client_public,
            &wg_server_public,
            timestamp,
        );

        assert!(pkgbuf.len() >= 4 + 4 + 8 + 32); // version + method + timestamp + auth_tag

        let version = u32::from_le_bytes([pkgbuf[0], pkgbuf[1], pkgbuf[2], pkgbuf[3]]);
        assert_eq!(version, 2);

        let method = u32::from_le_bytes([pkgbuf[4], pkgbuf[5], pkgbuf[6], pkgbuf[7]]);
        assert_eq!(method, 1);

        let extracted_timestamp = u64::from_le_bytes([
            pkgbuf[8], pkgbuf[9], pkgbuf[10], pkgbuf[11], pkgbuf[12], pkgbuf[13], pkgbuf[14],
            pkgbuf[15],
        ]);
        assert_eq!(extracted_timestamp, timestamp);
    }

    #[test]
    fn parse_response_error_v2() {
        // V2 error format: version (4) + method (4, = 2 for error) + code (4) = 12 bytes
        // Method 2 = MessageTypeError
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::ServerError))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::DeviceError))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::PeerOrDeviceNotFound))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::CouldNotReadTimestamp))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::CouldNotReadVersion))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x06\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::CouldNotReadMessageType))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::Failure))
        ));
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x08\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::AuthenticationFailed))
        ));

        // Pass unknown errors
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::UnhandledError))
        ));

        // Too short payload (less than 12 bytes)
        assert!(matches!(
            super::parse_response_payload(b"\x02\x00\x00\x00\x02\x00\x00\x00", 2),
            Err(Error::ServerV2(PqProtoV2Status::NoData))
        ));
    }

    use proptest::prelude::*;

    fn extract_auth_tag_from_payload(payload: &[u8]) -> [u8; 32] {
        // Auth tag is the last 32 bytes of the payload
        let auth_tag_start = payload.len() - 32;
        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(&payload[auth_tag_start..]);
        auth_tag
    }

    proptest! {
        #[test]
        fn test_auth_tag_is_the_same_for_same_inputs(
            pre_shared_key in any::<[u8; 32]>(),
            wg_client_public in any::<[u8; 32]>(),
            wg_server_public in any::<[u8; 32]>(),
            timestamp in any::<u64>(),
        ) {
            // There should be no hidden non determinism in the implementation
            let psk = telio_crypto::PresharedKey::new(pre_shared_key);
            let client = telio_crypto::PublicKey::from(&wg_client_public);
            let server = telio_crypto::PublicKey::from(&wg_server_public);

            let mut payload1 = Vec::new();
            super::push_rekey_method_udp_payload_v2_with_timestamp(&mut payload1, &psk, &client, &server, timestamp);
            let auth_tag1 = extract_auth_tag_from_payload(&payload1);

            let mut payload2 = Vec::new();
            super::push_rekey_method_udp_payload_v2_with_timestamp(&mut payload2, &psk, &client, &server, timestamp);
            let auth_tag2 = extract_auth_tag_from_payload(&payload2);

            prop_assert_eq!(auth_tag1, auth_tag2);
        }

        #[test]
        fn test_auth_tag_changes_with_different_inputs(
            pre_shared_key1 in any::<[u8; 32]>(),
            pre_shared_key2 in any::<[u8; 32]>(),
            wg_client_public1 in any::<[u8; 32]>(),
            wg_client_public2 in any::<[u8; 32]>(),
            wg_server_public1 in any::<[u8; 32]>(),
            wg_server_public2 in any::<[u8; 32]>(),
            timestamp1 in any::<u64>(),
            timestamp2 in any::<u64>()
        ) {
            let psk1 = telio_crypto::PresharedKey::new(pre_shared_key1);
            let psk2 = telio_crypto::PresharedKey::new(pre_shared_key2);
            let client1 = telio_crypto::PublicKey::from(&wg_client_public1);
            let client2 = telio_crypto::PublicKey::from(&wg_client_public2);
            let server1 = telio_crypto::PublicKey::from(&wg_server_public1);
            let server2 = telio_crypto::PublicKey::from(&wg_server_public2);

            let mut payload1 = Vec::new();
            super::push_rekey_method_udp_payload_v2_with_timestamp(&mut payload1, &psk1, &client1, &server1, timestamp1);
            let auth_tag1 = extract_auth_tag_from_payload(&payload1);

            let mut payload2 = Vec::new();
            super::push_rekey_method_udp_payload_v2_with_timestamp(&mut payload2, &psk2, &client2, &server2, timestamp2);
            let auth_tag2 = extract_auth_tag_from_payload(&payload2);

            let inputs_differ = psk1 != psk2 || client1 != client2 || server1 != server2 || timestamp1 != timestamp2;

            if inputs_differ {
                prop_assert_ne!(auth_tag1, auth_tag2);
            }
        }
    }
}
