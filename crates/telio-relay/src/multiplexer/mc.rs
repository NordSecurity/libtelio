use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::Wrapping,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    stream::{self, FusedStream},
    Sink, SinkExt, Stream, StreamExt,
};
use telio_crypto::PublicKey;
use telio_proto::{AnyPacket, Codec, PacketRelayed, PacketTypeRelayed};
use telio_task::io::Chan;
use tokio_util::sync::{PollSendError, PollSender};

type BoxFusedStream<'a, T> = Pin<Box<dyn FusedStream<Item = T> + Send + 'a>>;
type BoxSink<'a, T, E> = Pin<Box<dyn Sink<T, Error = E> + Send + 'a>>;

type InTx = BoxSink<'static, (PublicKey, PacketRelayed), SendError>;
type InRx = BoxFusedStream<'static, (PublicKey, PacketRelayed)>;

#[derive(Default)]
pub struct MultiChannel {
    last: Wrapping<usize>,
    channels: BTreeMap<usize, Channel>,
    mapping: HashMap<PacketTypeRelayed, usize>,
}

struct Channel {
    tx: InTx,
    tx_result: Option<Result<(), ()>>,
    tx_is_closed: Box<dyn Fn() -> bool + Send + 'static>,
    rx: InRx,
}

struct SendError;

impl MultiChannel {
    /// Create one piped channel for [T] packets.
    pub fn pipe<T: AnyPacket<PacketRelayed, PacketTypeRelayed> + 'static>(
        &mut self,
    ) -> Result<Chan<(PublicKey, T)>, ()> {
        self.cleanup();

        if self.mapping.keys().any(|k| T::TYPES.contains(k)) {
            return Err(());
        }

        let (in_chan, out_chan) = Chan::pipe();

        let Chan { tx, mut rx } = out_chan;

        let tx_is_closed = {
            let tx = tx.clone();
            Box::new(move || tx.is_closed())
        };

        let tx: InTx = Box::pin(PollSender::new(tx).with(
            |data: (PublicKey, PacketRelayed)| async move {
                Ok((data.0, T::downcast(data.1).map_err(|_| SendError)?))
            },
        ));

        let rx = Box::pin(
            stream::poll_fn(move |cx| {
                rx.poll_recv(cx)
                    .map(|msg| msg.map(|(pk, msg)| (pk, msg.into())))
            })
            .fuse(),
        );

        let id = self.last.0;
        self.channels.insert(
            self.last.0,
            Channel {
                tx,
                tx_result: None,
                tx_is_closed,
                rx,
            },
        );
        self.last += Wrapping(1);

        for pt in T::TYPES {
            let _ = self.mapping.insert(*pt, id);
        }

        Ok(in_chan)
    }

    fn cleanup(&mut self) {
        let ids: HashSet<_> = self
            .channels
            .iter()
            .filter(|(_, v)| { v.tx_is_closed.as_ref() }() || v.rx.is_terminated())
            .map(|(k, _)| *k)
            .collect();

        self.mapping.retain(|_, id| !ids.contains(id))
    }
}

impl Stream for MultiChannel {
    type Item = (PublicKey, PacketRelayed);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut dirty = false;
        for Channel { rx, .. } in self.channels.values_mut() {
            match rx.poll_next_unpin(cx) {
                Poll::Pending => (),
                Poll::Ready(Some(res)) => {
                    return Poll::Ready(Some(res));
                }
                Poll::Ready(None) => {
                    dirty = true;
                }
            }
        }

        if dirty {
            self.cleanup();
        }

        Poll::Pending
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SinkError {
    #[error("start_send called without poll_ready being called first")]
    StartSendBeforePollReady,
    #[error("Sending value to sink failed")]
    SendingFailed,
    #[error("poll_ready failed")]
    PollReadyFailed,
    #[error("Packet type {0:?} not in mapping")]
    MissingPacketType(PacketTypeRelayed),
    #[error("No channel for packet type {0:?} and id {1}")]
    MissingChannel(PacketTypeRelayed, usize),
}

impl Sink<(PublicKey, PacketRelayed)> for MultiChannel {
    type Error = SinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Ensure all channels are ready for send
        let mut ready = true;

        for chan in self.channels.values_mut() {
            if chan.tx_result.is_some() {
                continue;
            }
            match chan.tx.poll_ready_unpin(cx) {
                Poll::Ready(res) => chan.tx_result = Some(res.map_err(|_| ())),
                Poll::Pending => {
                    ready = false;
                }
            }
        }

        if ready {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: (PublicKey, PacketRelayed),
    ) -> Result<(), Self::Error> {
        let i = self
            .mapping
            .get(&item.1.packet_type())
            .copied()
            .ok_or_else(|| SinkError::MissingPacketType(item.1.packet_type()))?;
        let chan = self
            .channels
            .get_mut(&i)
            .ok_or_else(|| SinkError::MissingChannel(item.1.packet_type(), i))?;

        let res = chan
            .tx_result
            .take()
            .ok_or(SinkError::StartSendBeforePollReady)?;
        if res.is_err() {
            self.cleanup();
            return Err(SinkError::PollReadyFailed);
        }
        chan.tx.start_send_unpin(item).map_err(|_| {
            self.cleanup();
            SinkError::SendingFailed
        })
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        for chan in self.channels.values_mut() {
            // [PollSender] flush completes after single poll
            let _ = chan.tx.poll_flush_unpin(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        for chan in self.channels.values_mut() {
            // [PollSender] close completes after single poll
            let _ = chan.tx.poll_close_unpin(cx);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> From<PollSendError<T>> for SendError {
    fn from(_: PollSendError<T>) -> Self {
        SendError
    }
}

#[cfg(test)]
mod tests {
    use telio_crypto::SecretKey;
    use telio_proto::{DataMsg, HeartbeatMessage};

    use super::*;

    #[tokio::test]
    async fn test_send() {
        let mut mc = MultiChannel::default();
        let mut data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
        let mut nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");

        let pk1 = SecretKey::gen().public();
        let pk2 = SecretKey::gen().public();

        assert_eq!(Ok(()), mc.send((pk1, DataMsg::new(b"hello").into())).await);
        assert_eq!(Ok(()), mc.send((pk2, DataMsg::new(b"bye").into())).await);

        assert_eq!(
            Ok(()),
            mc.send((pk1, HeartbeatMessage::request().into())).await,
        );
        assert_eq!(
            Ok(()),
            mc.send((pk2, HeartbeatMessage::request().into())).await,
        );

        assert_eq!(Some((pk1, DataMsg::new(b"hello"))), data.rx.recv().await);
        assert_eq!(Some((pk2, DataMsg::new(b"bye"))), data.rx.recv().await);

        assert_eq!(
            Some((pk1, HeartbeatMessage::request())),
            nurse.rx.recv().await
        );
        assert_eq!(
            Some((pk2, HeartbeatMessage::request())),
            nurse.rx.recv().await
        );
    }

    #[tokio::test]
    async fn test_send_errors() {
        let pk1 = SecretKey::gen().public();

        let mut mc = MultiChannel::default();

        // Due to drop.
        {
            let _ = mc.pipe::<DataMsg>().expect("Failed to pipe data");
        }
        assert!(mc.send((pk1, DataMsg::new(b"noooo").into())).await.is_err());

        // Due to not piped type
        assert!(mc
            .send((pk1, HeartbeatMessage::request().into()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_mutiple_pipe_reuqests() {
        let mut mc = MultiChannel::default();
        let _data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
        assert!(mc.pipe::<DataMsg>().is_err())
    }

    #[tokio::test]
    async fn test_recv() {
        let mut mc = MultiChannel::default();
        let data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
        let nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");

        let pk1 = SecretKey::gen().public();
        let pk2 = SecretKey::gen().public();

        assert!(data.tx.send((pk1, DataMsg::new(b"hello"))).await.is_ok());
        assert!(data.tx.send((pk2, DataMsg::new(b"bye"))).await.is_ok());

        assert!(nurse
            .tx
            .send((pk1, HeartbeatMessage::request().into()))
            .await
            .is_ok());
        assert!(nurse
            .tx
            .send((pk2, HeartbeatMessage::request().into()))
            .await
            .is_ok());

        assert_eq!(Some((pk1, DataMsg::new(b"hello").into())), mc.next().await);
        assert_eq!(Some((pk2, DataMsg::new(b"bye").into())), mc.next().await);
        assert_eq!(
            Some((pk1, HeartbeatMessage::request().into())),
            mc.next().await
        );
        assert_eq!(
            Some((pk2, HeartbeatMessage::request().into())),
            mc.next().await
        );
    }

    #[tokio::test]
    async fn test_drop_switch() {
        let pk = SecretKey::gen().public();
        let dp = (pk, DataMsg::new(b"boo").into());
        let np = (pk, HeartbeatMessage::request().into());

        let mut mc = MultiChannel::default();
        // First creation.
        {
            let _data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
            let _nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");
            assert!(mc.send(dp.clone()).await.is_ok());
            assert!(mc.send(np.clone()).await.is_ok());
        }
        // Creation in reverse order.
        {
            let _nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");
            let _data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
            assert!(mc.send(dp.clone()).await.is_ok());
            assert!(mc.send(np.clone()).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_drop_of_singular_chans() {
        let pk = SecretKey::gen().public();
        let dp = (pk, DataMsg::new(b"boo").into());
        let np = (pk, HeartbeatMessage::request().into());

        let mut mc = MultiChannel::default();
        // Drop first
        {
            let _data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
            let _nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");
            drop(_data);
            assert!(mc.send(dp.clone()).await.is_err());
            assert!(mc.send(np.clone()).await.is_ok());
        }
        // Drop second
        {
            let _data: Chan<(_, DataMsg)> = mc.pipe().expect("Failed to pipe data");
            let _nurse: Chan<(_, HeartbeatMessage)> = mc.pipe().expect("Failed to pipe heartbeat");
            drop(_nurse);
            assert!(mc.send(dp.clone()).await.is_ok());
            assert!(mc.send(np.clone()).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_drop_of_rx() {
        let pk = SecretKey::gen().public();
        let dp = (pk, DataMsg::new(b"boo").into());

        let mut mc = MultiChannel::default();
        let Chan { tx: _tx, rx } = mc.pipe::<DataMsg>().expect("Failed to pipe data");

        drop(rx);
        assert!(mc.send(dp).await.is_err());
    }
}
