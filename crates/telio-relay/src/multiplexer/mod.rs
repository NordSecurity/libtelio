//! Module is used for distributing Derp traffic with other crates.

mod inout;
mod mc;

use std::future::Future;

use async_trait::async_trait;
use futures::{sink::SinkExt, stream::StreamExt};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::PollSender;

use telio_crypto::PublicKey;
use telio_proto::{AnyPacket, PacketRelayed, PacketTypeRelayed};
use telio_task::{io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_error, telio_log_generic};

use self::inout::InOut;
use self::mc::MultiChannel;

/// Multiplexer Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Component was stopped
    #[error("Component was stopped.")]
    Stopped,

    /// Packet Types already handled by other channel
    #[error("Packet Types already handled by other channel.")]
    Occupied,
}

/// Multiplexer task exposed to other crates
pub struct Multiplexer {
    task: Task<State>,
}

struct State {
    relay_tx: PollSender<(PublicKey, PacketRelayed)>,
    relay_rx: ReceiverStream<(PublicKey, PacketRelayed)>,
    multi_channel: InOut<MultiChannel, (PublicKey, PacketRelayed)>,
}

impl Multiplexer {
    /// Multiplexer constructor
    pub fn start(relay: Chan<(PublicKey, PacketRelayed)>) -> Self {
        Self {
            task: Task::start(State {
                // relay,
                relay_tx: PollSender::new(relay.tx),
                relay_rx: ReceiverStream::new(relay.rx),
                multi_channel: InOut::new(MultiChannel::default()),
            }),
        }
    }

    /// Change the relay, that communicates with lower relay module
    pub async fn change_output(&self, relay: Chan<(PublicKey, PacketRelayed)>) {
        let _ = task_exec!(&self.task, async move |s| {
            s.relay_tx = PollSender::new(relay.tx);
            s.relay_rx = ReceiverStream::new(relay.rx);
            Ok(())
        })
        .await;
    }

    /// Change the relay, that communicates with lower relay module
    pub async fn get_channel<T: AnyPacket<PacketRelayed, PacketTypeRelayed> + 'static>(
        &self,
    ) -> Result<Chan<(PublicKey, T)>, Error> {
        task_exec!(&self.task, async move |s| {
            let mc = match s.multi_channel.joined() {
                Ok(Some(mc)) => mc,
                Ok(None) => {
                    telio_log_error!("Failed to join multi_channel");
                    return Err(());
                }
                Err(e) => {
                    telio_log_error!("Failed to join multi_channel: {}", e);
                    return Err(());
                }
            };
            Ok(mc.pipe())
        })
        .await
        .map_err(|_| Error::Stopped)?
        .map_err(|_| Error::Occupied)
    }

    /// "Destructor"
    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Multiplexer";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        let (mc_tx, mc_rx) = match self.multi_channel.split() {
            Some(mc) => mc,
            None => {
                telio_log_error!("Failed to split multi_channel");
                return Err(());
            }
        };

        let mut mc_rx = mc_rx.by_ref().map(Result::Ok);
        let mut rl_rx = self.relay_rx.by_ref().map(Result::Ok);

        let update = tokio::select! {
            _ = self.relay_tx.send_all(&mut mc_rx) => {
                None
            }
            _ = mc_tx.send_all(&mut rl_rx) => {
                None
            }
            update = update => Some(update),
            else => None,
        };

        if let Some(update) = update {
            let _ = update(self).await;
            Ok(())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use telio_crypto::PublicKey;
    use telio_proto::{DataMsg, HeartbeatMessage};
    use telio_test::await_timeout;

    #[tokio::test(start_paused = true)]
    async fn test_destination_byte() {
        let payload = vec![0u8; 10];
        let pub_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        let (chan_l, mut output) = Chan::pipe();
        let multiplexer = Multiplexer::start(chan_l);

        // Data
        {
            let input_data = multiplexer.get_channel::<DataMsg>().await.unwrap();

            await_timeout!(input_data.tx.send((pub_key, DataMsg::new(&payload)))).unwrap();

            assert_eq!(
                await_timeout!(output.rx.recv()).unwrap(),
                (pub_key, PacketRelayed::Data(DataMsg::new(&payload)))
            );
        }

        // Heartbeat
        {
            let input_heart = multiplexer.get_channel::<HeartbeatMessage>().await.unwrap();

            let msg = HeartbeatMessage::request();
            await_timeout!(input_heart.tx.send((pub_key, msg.clone()))).unwrap();

            assert_eq!(
                await_timeout!(output.rx.recv()).unwrap(),
                (pub_key, PacketRelayed::Heartbeat(msg))
            );
        }

        // await_timeout!(multiplexer.stop());
    }
}
