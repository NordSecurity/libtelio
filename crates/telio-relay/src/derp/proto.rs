use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey as BoxPublicKey, SalsaBox,
};
use log::{log_enabled, Level::Debug, Level::Trace};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{
    convert::TryFrom,
    error::Error as StdError,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    time::Duration,
};
use telio_crypto::{PublicKey, SecretKey, KEY_SIZE};
use telio_utils::{telio_log_debug, telio_log_trace};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{Receiver, Sender},
};

#[cfg(windows)]
use static_assertions::const_assert;

/// 8 bytes of magic message prefix: `DERP🔑`
const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91];

/// Default value for connecting to server attempt
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default value for un-ack'ed packet timeout for TCP (mac: TCP_CONNECTIONTIMEOUT, linux-like: TCP_USER_TIMEOUT, windows: not supported)
pub const TCP_USER_TIMEOUT: Duration = Duration::from_secs(125);

/// Default value for keepalive idle
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(25);

/// Default value for keepalive probe count
pub const TCP_KEEPALIVE_COUNT: u32 = 3;

/// Default value for keepalive interval between probes
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Default value for how ofter derp sends keepalives
pub const DERP_KEEPALIVE_INTERVAL: u32 = 60;

/// Default value for how ofter derp sends tcp keepalives
pub const DERP_TCP_KEEPALIVE_INTERVAL: u32 = 15;

// Check, if value won't overflow, when setting them on WinSock::setsockopt
#[cfg(windows)]
const_assert!(
    ((TCP_USER_TIMEOUT.as_secs()) as u32 <= (i8::MAX as u32))
        && ((TCP_KEEPALIVE_IDLE.as_secs()) as u32 <= (i8::MAX as u32))
        && ((TCP_KEEPALIVE_INTERVAL.as_secs()) as u32 <= (i8::MAX as u32))
        && ((TCP_KEEPALIVE_COUNT as u32) <= (i8::MAX as u32))
);

#[repr(u8)]
#[derive(
    Debug, Hash, PartialEq, Eq, Copy, Clone, strum::EnumIter, TryFromPrimitive, IntoPrimitive,
)]
/// Descriptor of packet, for which telio types it is destined
pub enum FrameChannel {
    /// Ordinary user's data
    Data = 0x00,
    /// Natter requests/responses
    Natter = 0x01,
    /// Commander requests/responses
    Cmder = 0x02,
    /// Telio-nurse requests/responses
    Nurse = 0x03,

    /// Error
    Unknown = 0xFF,
}

#[repr(u8)]
#[derive(Debug, PartialEq, TryFromPrimitive)]
// These should be updated once server is updated
/// FrameType defines a type of a frame. Each frame type may have a different structure
/// Note: values 0x0A - 0x0F are skipped
enum FrameType {
    /// 8B magic + 32B public key + (0+ bytes future use)
    ServerKey = 0x01,
    /// 32B pub key + 24B nonce + naclbox(json)
    ClientInfo = 0x02,
    /// 24B nonce + naclbox(json)
    ServerInfo = 0x03,
    /// 32B dest pub key + packet bytes
    SendPacket = 0x04,
    /// v2: 32B src pub key + packet bytes
    RecvPacket = 0x05,
    /// no payload, no-op (to be replaced with ping/pong)
    KeepAlive = 0x06,
    /// 1 byte payload: 0x01 or 0x00 for whether this is client's home node
    NotePreferred = 0x07,
    /// PeerGone is sent from server to client to signal that
    /// a previous sender is no longer connected. That is, if A
    /// sent to B, and then if A disconnects, the server sends
    /// PeerGone to B so B can forget that a reverse path
    /// exists on that connection to get back to A.
    /// 32B pub key of peer that's gone
    PeerGone = 0x08,
    /// PeerPresent is like PeerGone, but for other
    /// members of the DERP region when they're meshed up together.
    /// 32B pub key of peer that's connected
    PeerPersistent = 0x09,
    /// WatchConns is how one DERP node in a regional mesh
    /// subscribes to the others in the region.
    /// There's no payload. If the sender doesn't have permission, the connection
    /// is closed. Otherwise, the client is initially flooded with
    /// PeerPresent for all connected nodes, and then a stream of
    /// PeerPresent & PeerGone has peers connect and disconnect.
    WatchConns = 0x10,
    /// ClosePeer is a privileged frame type (requires the
    /// mesh key for now) that closes the provided peer's
    /// connection. (To be used for cluster load balancing
    /// purposes, when clients end up on a non-ideal node)
    /// 32B pub key of peer to close.
    ClosePeer = 0x11,
    /// 8 byte ping payload, to be echoed back in Pong
    Ping = 0x12,
    /// 8 byte payload, the contents of the ping being replied to
    Pong = 0x13,
}

/// Error is a boxed std::error::Error
pub type Error = Box<dyn StdError>;

#[derive(Copy, Clone)]
pub struct PairAddr {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// This function starts a loop which reads all the frames from a reader, handles the known types
/// and bypasses the content of DERP frames to the reader_sender
#[allow(mpsc_blocking_send)]
pub async fn start_read<R: AsyncRead + Unpin>(
    mut reader: R,
    reader_sender: Sender<(PublicKey, Vec<u8>)>,
    addr: PairAddr,
) -> Result<(), Error> {
    loop {
        let (frame_type, mut data) = read_frame(&mut reader).await?;
        match frame_type {
            FrameType::RecvPacket => {
                let public_key =
                    <PublicKey as TryFrom<&[u8]>>::try_from(data.drain(0..KEY_SIZE).as_slice())?;

                if log_enabled!(Trace) {
                    // Glance at first byte, which describes the destination
                    let chan = FrameChannel::try_from(data[0]).unwrap_or(FrameChannel::Unknown);
                    telio_log_trace!(
                        "DERP Rx: {} -> {}, frame type: {:?}, data len: {}, pubkey: {:?}, channel: {:?}",
                        addr.remote,
                        addr.local,
                        frame_type,
                        data.len(),
                        public_key,
                        chan,
                    );
                }
                reader_sender.send((public_key, data)).await?
            }
            _ => telio_log_debug!("Unhandled packet: {:?}: {:?}", frame_type, data),
        }
    }
}

/// This function starts a loop which receives all the messages to the writer_receiver,
/// encapsulates them to DERP frames and bypasses them to the writer
pub async fn start_write<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut writer_receiver: Receiver<(PublicKey, Vec<u8>)>,
    addr: PairAddr,
) -> Result<(), Error> {
    while let Some((public_key, data)) = writer_receiver.recv().await {
        let mut buf = Vec::<u8>::new();
        buf.write_all(public_key.as_ref()).await?;
        buf.write_all(&data).await?;

        if log_enabled!(Trace) {
            // Glance at first byte, which describes the destination
            let chan = FrameChannel::try_from(data[0]).unwrap_or(FrameChannel::Unknown);
            telio_log_trace!(
                "DERP Tx: {} -> {}, data len: {}, pubkey: {:?}, channel: {:?}",
                addr.local,
                addr.remote,
                data.len(),
                public_key,
                chan,
            );
        }

        write_frame(&mut writer, FrameType::SendPacket, buf).await?;
    }

    Ok(())
}

/// Reads the server key and sends the initiation message via a writer to the DERP
/// server
/// Initiation message consists of:
/// * `public key`
/// * `nonce` - a random byte sequence generated by client
/// * `ciphertext` - an initiation JSON encrypted with the secret key, using a generated nonce
pub async fn exchange_keys<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    secret_key: SecretKey,
) -> Result<(), Error> {
    let server_key = read_server_key(&mut reader).await?;
    write_client_key(&mut writer, secret_key, server_key).await?;
    Ok(())
}

pub async fn read_server_info<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), Error> {
    let (frame_type, mut _bytes) = read_frame(reader).await?;
    if frame_type != FrameType::ServerInfo {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "invalid frame type for server info",
        )));
    }

    Ok(())
}

async fn write_client_key<W: AsyncWrite + Unpin>(
    writer: &mut W,
    secret_key: SecretKey,
    server_key: PublicKey,
) -> Result<(), Error> {
    let server_key = server_key.into();
    let secret_key = secret_key.into();
    let public_key = BoxPublicKey::from(&secret_key);

    telio_log_trace!("DERP starting with {}", PublicKey::from(public_key.clone()));

    let mut rng = rand_core::OsRng;
    let nonce = SalsaBox::generate_nonce(&mut rng);
    let plain_text = b"{\"version\": 2, \"meshKey\": \"\"}";
    let b = SalsaBox::new(&server_key, &secret_key);

    let ciphertext = b
        .encrypt(&nonce, &plain_text[..])
        .map_err(|err| -> Error { Box::new(IoError::new(ErrorKind::Other, err.to_string())) })?;

    let mut buf = Vec::<u8>::new();
    buf.write_all(public_key.as_bytes()).await?;
    buf.write_all(&nonce).await?;
    buf.write_all(&ciphertext).await?;
    write_frame(writer, FrameType::ClientInfo, buf).await
}

async fn read_server_key<R: AsyncRead + Unpin>(reader: &mut R) -> Result<PublicKey, Error> {
    let (frame_type, mut bytes) = read_frame(reader).await?;
    if frame_type != FrameType::ServerKey {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "invalid frame type for server key",
        )));
    }
    if bytes.len() < 40 {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "invalid server response length",
        )));
    }
    if bytes.drain(0..MAGIC.len()).as_slice() != MAGIC {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "server key should start with MAGIC sting",
        )));
    }

    <PublicKey as TryFrom<Vec<u8>>>::try_from(bytes).map_err(|_| -> Error {
        Box::new(IoError::new(
            ErrorKind::InvalidData,
            "invalid server public key",
        ))
    })
}

// TODO: Check if this approach is performant enough.
// Under normal circumstance self.reader is a TCP socket
// and it calls read() multiple times
/// Reads a DERP frame from a reader
/// Frame:
/// 0:1 - frame type
/// 1:4 - frame length
/// 5:frame_length+4 - frame content
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(FrameType, Vec<u8>), Error> {
    // Read header
    let mut buf = [0_u8; 1];

    reader.read_exact(&mut buf).await?;
    let frame_type = FrameType::try_from(buf[0])?;

    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf).await?;
    let frame_length = u32::from_be_bytes(buf);

    let mut buf = vec![0_u8; frame_length as usize];
    reader.read_exact(&mut buf).await?;
    Ok((frame_type, buf))
}

/// Writes a DERP frame to a writer
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame_type: FrameType,
    data: Vec<u8>,
) -> Result<(), Error> {
    let mut buf = Vec::<u8>::new();
    buf.write_all(&[frame_type as u8]).await?;
    buf.write_all(&u32::try_from(data.len())?.to_be_bytes())
        .await?;
    buf.write_all(&data).await?;
    writer.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    const KEY_MSG_SIZE: usize = 106;

    #[rstest]
    #[case(&[1, 0, 0, 0, 0], FrameType::ServerKey, "", false)]
    #[case(&[1, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'], FrameType::ServerKey, "hello", false)]
    #[case(&[2, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'], FrameType::ClientInfo, "", false)]
    #[case(&[1, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', b'!'], FrameType::ServerKey, "hello", false)]
    #[case(&[99, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', b'!'], FrameType::Ping, "", true)]
    #[case(&[], FrameType::ServerKey, "", true)]
    #[case(&[1], FrameType::ServerKey, "", true)]
    #[case(&[1, 0, 0, 0], FrameType::ServerKey, "", true)]
    async fn test_read_frame(
        #[case] mut data: &[u8],
        #[case] expected_frame_type: FrameType,
        #[case] expected_data: &str,
        #[case] error: bool,
    ) {
        match error {
            true => {
                assert_eq!(true, read_frame(&mut data).await.is_err());
            }
            false => {
                let (frame_type, buf) = read_frame(&mut data).await.unwrap();
                assert_eq!(expected_frame_type, frame_type);
                assert_eq!(expected_data.as_bytes(), buf);
            }
        }
    }

    #[rstest]
    #[case(FrameType::ServerKey, "", &[1, 0, 0, 0, 0], false)]
    #[case(FrameType::ServerKey, "hello", &[1, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'], false)]
    async fn test_write_frame(
        #[case] frame_type: FrameType,
        #[case] data: &str,
        #[case] expected_data: &[u8],
        #[case] error: bool,
    ) {
        let mut buf = Vec::new();
        match error {
            true => {
                assert_eq!(
                    true,
                    write_frame(&mut buf, frame_type, data.as_bytes().to_vec())
                        .await
                        .is_err()
                );
            }
            false => {
                write_frame(&mut buf, frame_type, data.as_bytes().to_vec())
                    .await
                    .unwrap();
                assert_eq!(expected_data, buf);
            }
        }
    }

    #[rstest]
    #[case(PublicKey([1_u8; KEY_SIZE]), [vec![1, 0, 0, 0, 40], MAGIC.to_vec(), vec![1_u8; KEY_SIZE]].concat(), false)]
    #[case(PublicKey([2_u8; KEY_SIZE]), [vec![1, 0, 0, 0, 40], MAGIC.to_vec(), vec![2_u8; KEY_SIZE]].concat(), false)]
    #[case(PublicKey([1_u8; KEY_SIZE]), [vec![2, 0, 0, 0, 40], MAGIC.to_vec(), vec![1_u8; KEY_SIZE]].concat(), true)]
    #[case(PublicKey([1_u8; KEY_SIZE]), [vec![1, 0, 0, 0, 41], MAGIC.to_vec(), vec![1_u8; KEY_SIZE]].concat(), true)]
    #[case(PublicKey([1_u8; KEY_SIZE]), [vec![1, 0, 0, 0, 40], vec![1_u8; 8], vec![1_u8; KEY_SIZE]].concat(), true)]
    async fn test_read_server_key(
        #[case] expected_server_key: PublicKey,
        #[case] data: Vec<u8>,
        #[case] error: bool,
    ) {
        let mut data = &data[..];
        match error {
            true => assert_eq!(true, read_server_key(&mut data).await.is_err()),
            false => {
                let server_key = read_server_key(&mut data).await.unwrap();
                assert_eq!(expected_server_key, server_key);
            }
        }
    }

    #[rstest]
    async fn test_write_client_key() {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        let mut buf3 = Vec::new();
        let secret_key1 = SecretKey([0_u8; KEY_SIZE]);
        let server_key1 = SecretKey([1_u8; KEY_SIZE]).public();
        let secret_key2 = SecretKey([2_u8; KEY_SIZE]);
        let server_key2 = SecretKey([3_u8; KEY_SIZE]).public();
        write_client_key(&mut buf1, secret_key1, server_key1)
            .await
            .unwrap();
        write_client_key(&mut buf2, secret_key1, server_key1)
            .await
            .unwrap();
        write_client_key(&mut buf3, secret_key2, server_key2)
            .await
            .unwrap();
        // nonce is generated everytime write_client_key is called, therefore the result must be
        // different in subsequent runs
        assert_ne!(buf1, buf2);
        assert_ne!(buf1, buf3);
        assert_ne!(buf2, buf3);
        assert_eq!(KEY_MSG_SIZE, buf1.len());
        assert_eq!(KEY_MSG_SIZE, buf2.len());
        assert_eq!(KEY_MSG_SIZE, buf3.len());
    }

    #[rstest]
    #[case([vec![1, 0, 0, 0, 40], MAGIC.to_vec(), vec![0_u8; KEY_SIZE]].concat(), [0_u8; KEY_SIZE], false)]
    #[case([vec![1, 0, 0, 0, 40], vec![0_u8; 8], vec![0_u8; KEY_SIZE]].concat(), [0_u8; KEY_SIZE], true)]
    async fn test_exchange_keys(
        #[case] reader: Vec<u8>,
        #[case] secret_key: [u8; KEY_SIZE],
        #[case] error: bool,
    ) {
        let reader = &reader[..];
        let mut writer = Vec::new();
        let secret_key = SecretKey(secret_key);
        match error {
            true => assert_eq!(
                true,
                exchange_keys(reader, &mut writer, secret_key)
                    .await
                    .is_err()
            ),
            false => {
                exchange_keys(reader, &mut writer, secret_key)
                    .await
                    .unwrap();
                assert_eq!(KEY_MSG_SIZE, writer.len());
            }
        }
    }
}
