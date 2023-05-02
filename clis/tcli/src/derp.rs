use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use clap::Parser;
use parking_lot::Mutex;
use serde::Deserialize;
use telio::crypto::SecretKey;
use telio_model::{config::Server, PublicKey};
use telio_proto::{Codec, Packet};
use telio_relay::{DerpRelay, SortedServers};
use telio_sockets::{NativeProtector, SocketPool};
use telio_task::io::{chan::Tx, Chan, McChan};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::{runtime::Runtime, task::JoinHandle};

use crate::{cli::Resp, cli_res, cli_try};

#[derive(Parser)]
/// Fake derp client
pub enum DerpClientCmd {
    /// Turn on DERP server module
    On {
        secret_key: SecretKey,
        servers: Vec<String>,
        allowed_pk: String,
    },
    /// Send bytes to peer.
    Send {
        public_key: PublicKey,
        bytes: Vec<u8>,
    },
    /// Print all recieved packets from peers.
    Recv,
    Events,
    /// Turn off DERP server module
    Off,
}

pub struct DerpClient {
    inst: Option<Instance>,
}

#[derive(Deserialize)]
pub struct Serv {
    pk: PublicKey,
    ipv4: Ipv4Addr,
    host: String,
    port: u16,
}

struct Instance {
    rt: Runtime,
    events: Arc<Mutex<Vec<Server>>>,
    packets: Arc<Mutex<Vec<(PublicKey, Packet)>>>,
    send: Tx<(PublicKey, Packet)>,
    collect: JoinHandle<()>,
    relay: DerpRelay,
}

impl DerpClient {
    pub fn new() -> Self {
        Self { inst: None }
    }

    pub fn exec_cmd(&mut self, cmd: DerpClientCmd) -> Vec<Resp> {
        use DerpClientCmd::*;
        let mut res = Vec::new();
        match cmd {
            On {
                secret_key,
                servers,
                allowed_pk,
            } => {
                let mut config = telio_relay::Config {
                    secret_key,
                    ..Default::default()
                };

                telio_log_debug!("Secret Key: {:?}", secret_key);

                config.servers = SortedServers::new(
                    servers
                        .into_iter()
                        .flat_map(|str_serv| {
                            if let Ok(server) = serde_json::from_str::<Serv>(&str_serv) {
                                telio_log_debug!("public Key (DERP SERVER): {:?}", &server.pk);
                                telio_log_debug!("port: {:?}", &server.port);
                                Some(Server {
                                    public_key: server.pk,
                                    ipv4: server.ipv4,
                                    hostname: server.host,
                                    relay_port: server.port,
                                    ..Default::default()
                                })
                            } else {
                                telio_log_warn!("Could not parse JSON as a Server");
                                None
                            }
                        })
                        .collect(),
                );

                let keys = allowed_pk.split(' ');
                for key in keys {
                    config.allowed_pk.insert(cli_try!(res; key.parse()));
                }

                if let Some(inst) = &mut self.inst {
                    inst.rt.block_on(inst.relay.configure(Some(config)));
                } else {
                    let rt = cli_try!(res; Runtime::new());
                    let (lpacket, rpacket) = Chan::pipe();
                    let McChan {
                        rx: mut event_rx,
                        tx: event_tx,
                    }: McChan<Box<Server>> = McChan::default();
                    let send = lpacket.tx;
                    let events: Arc<Mutex<Vec<Server>>> = Arc::new(Mutex::new(Vec::new()));
                    let packets = Arc::new(Mutex::new(Vec::new()));
                    let collect = rt.spawn({
                        let events = events.clone();
                        let packets = packets.clone();
                        let mut packet_rx = lpacket.rx;
                        async move {
                            loop {
                                tokio::select! {
                                    Some(msg) = packet_rx.recv() => {
                                        packets.lock().push(msg);
                                    }
                                    Ok(ev) = event_rx.recv() => {
                                        events.lock().push(*ev);
                                    }
                                    else => return,
                                }
                            }
                        }
                    });
                    // This will not work on mac/win due to not provided tunnel interface to socketpool
                    match NativeProtector::new(
                        #[cfg(target_os = "macos")]
                        Some(false),
                    ) {
                        Ok(protector) => {
                            let relay = DerpRelay::start_with(
                                rpacket,
                                Arc::new(SocketPool::new(protector)),
                                event_tx,
                            );
                            self.inst = Some(Instance {
                                rt,
                                events,
                                packets,
                                send,
                                collect,
                                relay,
                            });
                        }
                        Err(e) => res.push(Resp::Error(Box::new(e.into()))),
                    };
                }
            }
            Send { public_key, bytes } => {
                if let Some(inst) = &mut self.inst {
                    let packet = cli_try!(Packet::decode(&bytes));
                    let _ = inst.send.blocking_send((public_key, packet));
                }
            }
            Recv => {
                if let Some(inst) = &mut self.inst {
                    for (pk, packet) in inst.packets.lock().drain(..) {
                        // TODO: Improve printing form personal needs.
                        cli_res!(res; (i "{}: {:?}", pk, packet))
                    }
                }
            }
            Events => {
                if let Some(inst) = &mut self.inst {
                    for event in inst.events.lock().drain(..) {
                        // TODO: Improve printing form personal needs. json could be used
                        cli_res!(res; (i "{:?}", event))
                    }
                }
            }
            Off => {
                if let Some(inst) = self.inst.take() {
                    inst.rt.block_on(inst.relay.stop());
                    inst.collect.abort();
                    inst.rt.shutdown_timeout(Duration::from_secs(1));
                }
            }
        }

        res
    }
}
