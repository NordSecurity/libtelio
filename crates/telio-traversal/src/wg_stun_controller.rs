use async_trait::async_trait;
use futures::Future;
use std::sync::Arc;
use std::time::Duration;
use telio_task::{io::chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_error};
use telio_wg::{DynamicWg, WireGuard};
use tokio::time::{interval_at, Interval};

pub type WgStunConfig = telio_relay::derp::Config;
pub type WgStunServer = telio_relay::derp::Server;

pub struct WgStunController<T: WireGuard = DynamicWg> {
    task: Task<State<T>>,
}

struct State<T: WireGuard> {
    wg_stun_peer_publisher: chan::Tx<Option<WgStunServer>>,
    wireguard_interface: Arc<T>,
    config: Option<WgStunConfig>,
    current_server: Option<WgStunServer>,
    poll_timer: Interval,
}

impl<T: WireGuard> WgStunController<T> {
    pub fn new(
        wg_stun_peer_publisher: chan::Tx<Option<WgStunServer>>,
        wireguard_interface: Arc<T>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            task: Task::start(State {
                wg_stun_peer_publisher,
                wireguard_interface,
                config: None,
                current_server: None,
                poll_timer: interval_at(tokio::time::Instant::now(), poll_interval),
            }),
        }
    }

    pub async fn configure(&self, config: Option<WgStunConfig>) {
        let _ = task_exec!(&self.task, async move |s| {
            s.configure(config).await;
            Ok(())
        })
        .await;
    }

    pub async fn get_config(&self) -> Option<WgStunConfig> {
        task_exec!(&self.task, async move |s| Ok(s.config.as_ref().cloned()))
            .await
            .ok()
            .flatten()
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    async fn tick(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            s.next().await;
            Ok(())
        })
        .await;
    }
}

impl<T: WireGuard> State<T> {
    #[allow(mpsc_blocking_send)]
    async fn configure(&mut self, config: Option<WgStunConfig>) {
        if self.config == config {
            return;
        }

        self.config = config;
        if let Some(c) = self.config.as_mut() {
            c.reset();
        } else {
            self.wg_stun_peer_publisher
                .send(None)
                .await
                .unwrap_or_else(|e| {
                    telio_log_error!("Error: {}", e);
                });
        }
        self.next().await;
    }

    async fn is_current_connection_healthy(&self) -> bool {
        if let Some(current_server) = self.current_server.as_ref() {
            return match self
                .wireguard_interface
                .time_since_last_rx(current_server.public_key)
                .await
            {
                Ok(Some(duration)) => duration < Duration::from_secs(30),
                Ok(None) => false,
                Err(_) => false,
            };
        }
        false
    }

    fn get_next_server(&mut self) -> Option<WgStunServer> {
        if let Some(config) = self.config.as_mut() {
            match config.get_server() {
                Some(server) => Some(server),
                None => {
                    telio_log_debug!("WG STUN server list exhausted, reseting config ...");
                    config.reset();
                    match config.get_server() {
                        Some(server) => Some(server),
                        None => {
                            telio_log_debug!("WG STUN server list empty");
                            None
                        }
                    }
                }
            }
        } else {
            None
        }
    }

    #[allow(mpsc_blocking_send)]
    async fn next(&mut self) {
        if !self.is_current_connection_healthy().await {
            self.current_server = self.get_next_server();
            if let Some(next_server) = &self.current_server {
                self.wg_stun_peer_publisher
                    .send(Some(next_server.clone()))
                    .await
                    .unwrap_or_else(|e| {
                        telio_log_error!("Error: {}", e);
                    });
            }
        }
    }
}

#[async_trait]
impl<T: WireGuard> Runtime for State<T> {
    const NAME: &'static str = "WgStunController";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            _ = self.poll_timer.tick() => {
                self.next().await;
            },
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telio_task::io::Chan;
    use telio_wg::MockWireGuard;

    fn get_test_config() -> WgStunConfig {
        let server1 = WgStunServer {
            name: "Server1".to_owned(),
            weight: 100,
            ..Default::default()
        };

        let server2 = WgStunServer {
            name: "Server2".to_owned(),
            weight: 200,
            ..Default::default()
        };

        let server3 = WgStunServer {
            name: "Server3".to_owned(),
            weight: 10,
            ..Default::default()
        };

        let mut config = WgStunConfig::default();
        config.servers.push(server1.clone());
        config.servers.push(server2.clone());
        config.servers.push(server3.clone());

        config
    }

    #[tokio::test]
    async fn server_changed_when_current_connection_is_broken() {
        let mut wg_mock = MockWireGuard::new();
        wg_mock
            .expect_time_since_last_rx()
            .returning(|_| Ok(Some(Duration::from_secs(40))));

        let mut wg_stun_peer_channel = Chan::<Option<WgStunServer>>::default();
        let controller = WgStunController::new(
            wg_stun_peer_channel.tx.clone(),
            Arc::new(wg_mock),
            Duration::from_secs(10000),
        );

        let config = get_test_config();
        controller.configure(Some(config.clone())).await;

        let received = wg_stun_peer_channel.rx.recv().await.unwrap();
        assert!(received == Some(config.servers[2].clone()));

        controller.tick().await;

        let received = wg_stun_peer_channel.rx.recv().await.unwrap();
        assert!(received == Some(config.servers[0].clone()));

        controller.tick().await;

        let received = wg_stun_peer_channel.rx.recv().await.unwrap();
        assert!(received == Some(config.servers[1].clone()));

        controller.tick().await;

        let received = wg_stun_peer_channel.rx.recv().await.unwrap();
        assert!(received == Some(config.servers[2].clone()));
    }

    #[tokio::test]
    async fn server_maintained_when_current_connection_is_active() {
        let mut wg_mock = MockWireGuard::new();
        wg_mock
            .expect_time_since_last_rx()
            .returning(|_| Ok(Some(Duration::from_secs(25))));

        let mut wg_stun_peer_channel = Chan::<Option<WgStunServer>>::default();
        let controller = WgStunController::new(
            wg_stun_peer_channel.tx.clone(),
            Arc::new(wg_mock),
            Duration::from_secs(10000),
        );

        let config = get_test_config();
        controller.configure(Some(config.clone())).await;

        let received = wg_stun_peer_channel.rx.recv().await.unwrap();
        assert!(received == Some(config.servers[2].clone()));

        controller.tick().await;
        wg_stun_peer_channel
            .rx
            .try_recv()
            .expect_err("Should not happen!");

        controller.tick().await;
        wg_stun_peer_channel
            .rx
            .try_recv()
            .expect_err("Should not happen!");
    }
}
