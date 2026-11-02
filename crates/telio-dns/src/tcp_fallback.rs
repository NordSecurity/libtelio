//! Retry of a truncated UDP answer over TCP against the same upstream

use crate::{
    bind_tun::bind_to_tun,
    nameserver::TCP_FALLBACK_MAX_RESPONSE,
    packet_decoder::edns_udp_payload_size,
    udp_forwarder::{get_dns_id, is_truncated},
};
use std::{convert::TryFrom, io, net::SocketAddr};
use telio_utils::{sleep_until, telio_log_debug, Instant};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};

/// Length prefix of a DNS message over TCP
const TCP_LEN_PREFIX: usize = 2;
/// UDP payload size every DNS client accepts (RFC 1035), EDNS values below it count as it (RFC 6891)
const MIN_UDP_PAYLOAD: u16 = 512;

/// Reasons a TCP fallback is abandoned
#[derive(Debug, Error)]
enum TcpFallbackError {
    #[error("Query size wrong: {0}")]
    BadQuerySize(usize),
    #[error("Answer size wrong: {0}")]
    BadAnswerSize(usize),
    #[error("Answer ID mismatch")]
    IdMismatch,
    #[error("Answer truncated")]
    Truncated,
    #[error("Timeout reached")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Largest answer that can be returned to the client over UDP
///
/// Bounded by the client's EDNS UDP payload size and by what fits in one tunnel packet
fn max_reply_len(query: &[u8]) -> usize {
    edns_udp_payload_size(query).map_or(TCP_FALLBACK_MAX_RESPONSE, |size| {
        usize::from(size.max(MIN_UDP_PAYLOAD)).min(TCP_FALLBACK_MAX_RESPONSE)
    })
}

/// Send `query` over a new tunnel bound TCP connection and read one framed reply of at most `max_len` bytes
async fn tcp_exchange(
    upstream: SocketAddr,
    query: &[u8],
    max_len: usize,
) -> Result<Vec<u8>, TcpFallbackError> {
    let len =
        u16::try_from(query.len()).map_err(|_| TcpFallbackError::BadQuerySize(query.len()))?;
    let socket = match upstream {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    bind_to_tun(&socket)?;
    let mut stream = socket.connect(upstream).await?;

    let mut framed = Vec::with_capacity(TCP_LEN_PREFIX + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;

    let mut prefix = [0u8; TCP_LEN_PREFIX];
    stream.read_exact(&mut prefix).await?;
    let reply_len = usize::from(u16::from_be_bytes(prefix));
    // Rejected before reading the body, so an oversized answer costs neither memory nor tunnel time
    if reply_len > max_len {
        return Err(TcpFallbackError::BadAnswerSize(reply_len));
    }
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// Check that a TCP reply answers `query_id` and can be returned over UDP
fn accept_tcp_reply(reply: Vec<u8>, query_id: u16) -> Result<Vec<u8>, TcpFallbackError> {
    let reply_id = get_dns_id(&reply).map_err(|_| TcpFallbackError::BadAnswerSize(reply.len()))?;
    if reply_id != query_id {
        return Err(TcpFallbackError::IdMismatch);
    }
    if is_truncated(&reply) {
        return Err(TcpFallbackError::Truncated);
    }
    Ok(reply)
}

/// Retry a query over TCP, returning the truncated reply if that fails
pub(crate) async fn tcp_fallback(
    upstream: SocketAddr,
    query: &[u8],
    deadline: Instant,
    truncated_reply: Vec<u8>,
) -> Vec<u8> {
    let exchange = async {
        let query_id =
            get_dns_id(query).map_err(|_| TcpFallbackError::BadQuerySize(query.len()))?;
        let reply = tcp_exchange(upstream, query, max_reply_len(query)).await?;
        accept_tcp_reply(reply, query_id)
    };

    let result = tokio::select! {
        res = exchange => res,
        _ = sleep_until(deadline) => Err(TcpFallbackError::Timeout),
    };

    result.unwrap_or_else(|e| {
        telio_log_debug!("TCP fallback to {upstream} failed: {e}");
        truncated_reply
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        nameserver::QUERY_TIMEOUT,
        packet_decoder::tests::{build_dns_query_bytes, push_opt},
        packet_encoder::DNS_HEADER_OFFSET,
        udp_forwarder::tests::{
            make_dns_packet, set_tc, BLACKHOLE_QUERY_TIMEOUT, TEST_DNS_PAYLOAD, TEST_PACKET_ID,
        },
    };
    use dns_parser::QueryType;
    use std::time::Duration;
    use tokio::{net::TcpListener, task::JoinHandle};

    const EDNS_ABOVE_TUNNEL_LIMIT: u16 = 4096;

    /// Build a TXT query, advertising `max_payload` over EDNS if given
    fn edns_query(max_payload: Option<u16>) -> Vec<u8> {
        let mut query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        if let Some(size) = max_payload {
            push_opt(&mut query, size);
        }
        query
    }

    /// Build one length prefixed DNS over TCP frame around `body`
    pub(crate) fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    pub(crate) enum TcpStubBehavior {
        /// Reply with the received query, zero padded to `pad_to` bytes
        Echo {
            pad_to: usize,
        },
        /// Same as Echo, but the length prefix and body are written separately with a pause
        EchoSplit {
            pad_to: usize,
        },
        EchoWrongId,
        EchoTruncated,
        /// Accept and never reply
        Stall,
        /// Accept and close
        Close,
        /// Read the query, then wait until the forwarder closes the connection
        WaitForClose,
    }

    /// Accept one connection on `listener`, return the raw bytes of the received frame
    pub(crate) fn spawn_tcp_stub(
        listener: TcpListener,
        behavior: TcpStubBehavior,
    ) -> JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if let TcpStubBehavior::Close = behavior {
                return Vec::new();
            }

            let mut prefix = [0u8; 2];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            stream.read_exact(&mut query).await.unwrap();
            let received = frame(&query);

            let mut answer = query;
            match behavior {
                TcpStubBehavior::Echo { pad_to } | TcpStubBehavior::EchoSplit { pad_to } => {
                    if answer.len() < pad_to {
                        answer.resize(pad_to, 0);
                    }
                }
                TcpStubBehavior::EchoWrongId => answer[0] ^= 0xFF,
                TcpStubBehavior::EchoTruncated => set_tc(&mut answer),
                TcpStubBehavior::Stall => {
                    std::future::pending::<()>().await;
                }
                TcpStubBehavior::WaitForClose => {
                    let mut probe = [0u8; 1];
                    while stream.read(&mut probe).await.unwrap() != 0 {}
                    return received;
                }
                TcpStubBehavior::Close => unreachable!(),
            }

            let framed = frame(&answer);
            if let TcpStubBehavior::EchoSplit { .. } = behavior {
                stream.write_all(&framed[..1]).await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                stream.write_all(&framed[1..]).await.unwrap();
            } else {
                stream.write_all(&framed).await.unwrap();
            }
            received
        })
    }

    async fn tcp_stub(behavior: TcpStubBehavior) -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, spawn_tcp_stub(listener, behavior))
    }

    fn truncated_reply() -> Vec<u8> {
        let mut reply = make_dns_packet(TEST_PACKET_ID, b"truncated-reply");
        set_tc(&mut reply);
        reply
    }

    fn fallback_query() -> Vec<u8> {
        edns_query(Some(EDNS_ABOVE_TUNNEL_LIMIT))
    }

    async fn fallback_with(behavior: TcpStubBehavior) -> Vec<u8> {
        fallback_with_query(&fallback_query(), behavior).await
    }

    async fn fallback_with_query(query: &[u8], behavior: TcpStubBehavior) -> Vec<u8> {
        let (addr, _stub) = tcp_stub(behavior).await;
        tcp_fallback(
            addr,
            query,
            Instant::now() + QUERY_TIMEOUT,
            truncated_reply(),
        )
        .await
    }

    #[test]
    fn max_reply_len_follows_client_edns_size() {
        assert_eq!(max_reply_len(&edns_query(Some(1232))), 1232);
    }

    #[test]
    fn max_reply_len_is_capped_to_one_tunnel_packet() {
        assert_eq!(
            max_reply_len(&edns_query(Some(EDNS_ABOVE_TUNNEL_LIMIT))),
            TCP_FALLBACK_MAX_RESPONSE
        );
    }

    #[test]
    fn max_reply_len_without_edns_is_one_tunnel_packet() {
        assert_eq!(max_reply_len(&edns_query(None)), TCP_FALLBACK_MAX_RESPONSE);
    }

    #[test]
    fn max_reply_len_treats_edns_below_512_as_512() {
        assert_eq!(max_reply_len(&edns_query(Some(100))), 512);
    }

    #[test]
    fn max_reply_len_of_unparsable_query_is_one_tunnel_packet() {
        assert_eq!(
            max_reply_len(&make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD)),
            TCP_FALLBACK_MAX_RESPONSE
        );
    }

    #[test]
    fn accept_tcp_reply_rejects_short_wrong_id_and_tc() {
        let id = TEST_PACKET_ID;
        let valid = |len: usize| {
            let mut reply = make_dns_packet(id, &[]);
            reply.resize(len, 0);
            reply
        };

        assert!(matches!(
            accept_tcp_reply(valid(DNS_HEADER_OFFSET - 1), id),
            Err(TcpFallbackError::BadAnswerSize(_))
        ));
        assert!(matches!(
            accept_tcp_reply(valid(DNS_HEADER_OFFSET), id ^ 1),
            Err(TcpFallbackError::IdMismatch)
        ));
        let mut truncated = valid(DNS_HEADER_OFFSET);
        set_tc(&mut truncated);
        assert!(matches!(
            accept_tcp_reply(truncated, id),
            Err(TcpFallbackError::Truncated)
        ));

        let at_limit = valid(TCP_FALLBACK_MAX_RESPONSE);
        assert_eq!(accept_tcp_reply(at_limit.clone(), id).unwrap(), at_limit);
    }

    #[tokio::test]
    async fn tcp_exchange_rejects_oversize_prefix_without_reading_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _stub = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        });

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            tcp_exchange(addr, &fallback_query(), TCP_FALLBACK_MAX_RESPONSE),
        )
        .await
        .expect("must not wait for the announced body");

        assert!(matches!(
            result,
            Err(TcpFallbackError::BadAnswerSize(len)) if len == usize::from(u16::MAX)
        ));
    }

    #[tokio::test]
    async fn tcp_exchange_rejects_query_too_long() {
        let query = vec![0u8; usize::from(u16::MAX) + 1];
        let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();

        assert!(matches!(
            tcp_exchange(unused, &query, TCP_FALLBACK_MAX_RESPONSE).await,
            Err(TcpFallbackError::BadQuerySize(len)) if len == query.len()
        ));
    }

    #[tokio::test]
    async fn tcp_fallback_returns_tcp_answer() {
        let result = fallback_with(TcpStubBehavior::Echo { pad_to: 1500 }).await;

        assert_eq!(result.len(), 1500);
        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert!(!is_truncated(&result));
    }

    #[tokio::test]
    async fn tcp_fallback_reads_split_frame() {
        let result = fallback_with(TcpStubBehavior::EchoSplit { pad_to: 1500 }).await;

        assert_eq!(result.len(), 1500);
        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert!(!is_truncated(&result));
    }

    #[tokio::test]
    async fn tcp_fallback_sends_framed_query() {
        let (addr, stub) = tcp_stub(TcpStubBehavior::Echo { pad_to: 0 }).await;

        tcp_fallback(
            addr,
            &fallback_query(),
            Instant::now() + QUERY_TIMEOUT,
            truncated_reply(),
        )
        .await;

        assert_eq!(stub.await.unwrap(), frame(&fallback_query()));
    }

    #[tokio::test]
    async fn tcp_fallback_at_size_limit_returns_tcp_answer() {
        let result = fallback_with(TcpStubBehavior::Echo {
            pad_to: TCP_FALLBACK_MAX_RESPONSE,
        })
        .await;

        assert_eq!(result.len(), TCP_FALLBACK_MAX_RESPONSE);
    }

    #[tokio::test]
    async fn tcp_fallback_oversize_returns_truncated_reply() {
        let result = fallback_with(TcpStubBehavior::Echo {
            pad_to: TCP_FALLBACK_MAX_RESPONSE + 1,
        })
        .await;

        assert_eq!(result, truncated_reply());
    }

    #[tokio::test]
    async fn tcp_fallback_answer_at_client_edns_size_is_returned() {
        let result = fallback_with_query(
            &edns_query(Some(1232)),
            TcpStubBehavior::Echo { pad_to: 1232 },
        )
        .await;

        assert_eq!(result.len(), 1232);
    }

    #[tokio::test]
    async fn tcp_fallback_answer_over_client_edns_size_returns_truncated_reply() {
        let result = fallback_with_query(
            &edns_query(Some(1232)),
            TcpStubBehavior::Echo { pad_to: 1233 },
        )
        .await;

        assert_eq!(result, truncated_reply());
    }

    #[tokio::test]
    async fn tcp_fallback_without_edns_returns_answer_over_512() {
        let result =
            fallback_with_query(&edns_query(None), TcpStubBehavior::Echo { pad_to: 513 }).await;

        assert_eq!(result.len(), 513);
    }

    #[tokio::test]
    async fn tcp_fallback_without_edns_over_one_tunnel_packet_returns_truncated_reply() {
        let result = fallback_with_query(
            &edns_query(None),
            TcpStubBehavior::Echo {
                pad_to: TCP_FALLBACK_MAX_RESPONSE + 1,
            },
        )
        .await;

        assert_eq!(result, truncated_reply());
    }

    #[tokio::test]
    async fn tcp_fallback_wrong_id_returns_truncated_reply() {
        assert_eq!(
            fallback_with(TcpStubBehavior::EchoWrongId).await,
            truncated_reply()
        );
    }

    #[tokio::test]
    async fn tcp_fallback_tc_answer_returns_truncated_reply() {
        assert_eq!(
            fallback_with(TcpStubBehavior::EchoTruncated).await,
            truncated_reply()
        );
    }

    #[tokio::test]
    async fn tcp_fallback_closed_connection_returns_truncated_reply() {
        assert_eq!(
            fallback_with(TcpStubBehavior::Close).await,
            truncated_reply()
        );
    }

    #[tokio::test]
    async fn tcp_fallback_connect_refused_returns_truncated_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = tcp_fallback(
            addr,
            &fallback_query(),
            Instant::now() + QUERY_TIMEOUT,
            truncated_reply(),
        )
        .await;

        assert_eq!(result, truncated_reply());
    }

    #[tokio::test]
    async fn tcp_fallback_stall_returns_truncated_reply_at_deadline() {
        let (addr, _stub) = tcp_stub(TcpStubBehavior::Stall).await;
        let start = Instant::now();

        let result = tcp_fallback(
            addr,
            &fallback_query(),
            start + BLACKHOLE_QUERY_TIMEOUT,
            truncated_reply(),
        )
        .await;

        let elapsed = Instant::now().duration_since(start);
        assert_eq!(result, truncated_reply());
        assert!(elapsed >= BLACKHOLE_QUERY_TIMEOUT, "{:?}", elapsed);
        assert!(
            elapsed < BLACKHOLE_QUERY_TIMEOUT + Duration::from_millis(500),
            "{:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn tcp_fallback_past_deadline_returns_truncated_reply() {
        let (addr, _stub) = tcp_stub(TcpStubBehavior::Stall).await;
        let start = Instant::now();

        let result = tcp_fallback(addr, &fallback_query(), start, truncated_reply()).await;

        assert_eq!(result, truncated_reply());
        assert!(Instant::now().duration_since(start) < Duration::from_millis(100));
    }
}
