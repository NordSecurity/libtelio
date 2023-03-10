use crate::derp::{DerpClient, DerpClientCmd};
use clap::Parser;
use flexi_logger::{DeferredNow, FileSpec, Logger, Record, WriteMode};
use ipnetwork::IpNetwork;
use log::error;
use serde::{Deserialize, Serialize};
use telio::crypto::{PublicKey, SecretKey};
use telio::device::{Device, DeviceConfig};
use telio_model::api_config::Features;
use telio_model::{config::Config as MeshMap, event::Event as DevEvent, mesh::ExitNode};
use telio_proto::{Codec, CodecError, Packet, PingType};
use telio_sockets::SocketPool;
use telio_traversal::routes::stunner::{Config as StunConfig, Stunner};
use telio_wg::AdapterType;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    runtime::Runtime,
    time::{sleep, Duration},
};

use crate::nord::{Error as NordError, Nord, OAuth};

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
};

#[cfg(target_os = "linux")]
const FWMARK_VALUE: u32 = 11673110;

#[cfg(windows)]
const DEFAULT_TUNNEL_NAME: &str = "NordLynx";

#[cfg(target_os = "linux")]
const DEFAULT_TUNNEL_NAME: &str = "nlx0";

#[cfg(target_os = "macos")]
const DEFAULT_TUNNEL_NAME: &str = "utun10";

trait Report {
    fn report(&self, cmd: StatusCmd) -> Vec<Resp>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("device must be started.")]
    NotStarted,

    #[error("login is needed")]
    NeedsLogin,

    #[error(transparent)]
    Telio(#[from] telio::device::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] shellwords::MismatchedQuotes),

    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    KeyDecode(#[from] base64::DecodeError),

    #[error(transparent)]
    Nord(#[from] NordError),

    #[error("bad command: {0:?}")]
    Parser(clap::ErrorKind),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Codec(#[from] CodecError),
}

pub struct Cli {
    telio: Device,
    resp: Receiver<Resp>,
    auth: Option<OAuth>,
    nord: Option<Nord>,
    conf: Option<MeshConf>,
    derp_client: DerpClient,
}

pub enum Resp {
    Info(String),
    Event(Box<DevEvent>),
    Error(Box<Error>),
    Quit,
}

#[derive(Deserialize, Serialize, Clone)]
struct MeshConf {
    name: String,
    sk: SecretKey,
    pk: PublicKey,
    id: String,
}

#[derive(Parser)]
#[clap(help_template = "commands:\n{subcommands}")]
enum Cmd {
    #[clap(subcommand)]
    Status(StatusCmd),
    #[clap(subcommand)]
    Login(LoginCmd),
    Events,
    #[clap(subcommand)]
    Dev(DevCmd),
    #[clap(subcommand)]
    Vpn(VpnCmd),
    #[clap(subcommand)]
    Mesh(MeshCmd),
    #[clap(subcommand)]
    Dns(DnsCmd),
    #[clap(subcommand)]
    Nat(DetectCmd),
    #[clap(subcommand)]
    Derp(DerpClientCmd),
    Quit,
}

#[derive(Parser)]
#[clap(about = "Status about telio, nodes, derp")]
enum StatusCmd {
    #[clap(about = "Print status as json string")]
    Simple,
    #[clap(about = "Print status as formatted json")]
    Pretty,
}

#[derive(Parser)]
#[clap(about = "Authorize to NordVPN API")]
enum LoginCmd {
    #[clap(about = "Authorize via OAuth login flow")]
    Oauth,
    #[clap(about = "Authorize with username and password (may not work")]
    Password { username: String, password: String },
    #[clap(about = "Authorize with authorization token")]
    Token { token: String },
}

#[derive(Parser)]
#[clap(about = "Direct device control")]
enum DevCmd {
    Start {
        /// Select adapter type to run
        #[clap(possible_values = &["boringtun", "wireguard-go", "wireguard-nt", "linux-native", ""], default_value ="")]
        adapter: String,
        /// Name of device
        #[clap(default_value = DEFAULT_TUNNEL_NAME)]
        name: String,
        /// Specify private_key to use instead of one provided from login
        private_key: Option<SecretKey>,
    },
    #[clap(about = "Connect to node")]
    Con {
        public_key: PublicKey,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<IpNetwork>,
    },
    #[clap(about = "Disconnect from node")]
    Dis {
        public_key: PublicKey,
    },
    #[clap(about = "Disconnect from all exit nodes")]
    Disall,
    #[clap(about = "Restarts telio wg adapter")]
    NotifyNetChange,
    Stop,
}

#[derive(Parser)]
enum VpnCmd {
    #[clap(about = "Connect to vpn server.")]
    On,
    #[clap(about = "Disconnect from vpn server.")]
    Off,
}

#[derive(Parser)]
enum MeshCmd {
    /// Turn mesnet on
    On {
        name: String,
    },
    /// Register to mesh as with some name
    Register {
        name: String,
    },
    ///Pinger tes
    Ping {},
    /// Stun test
    Stun {},
    /// Manually set json config
    Config {
        mesh_config: String,
    },
    Off,
}

#[derive(Parser)]
enum DnsCmd {
    /// Turn on DNS module
    On { forward_servers: Vec<String> },
    /// Turn off DNS module
    Off,
}

#[derive(Parser)]
#[clap(about = "Detect NAT type using stun binding requests ( RFC 3489 )")]
enum DetectCmd {
    Address { stun_server: String },
}

#[macro_export]
macro_rules! cli_res {
    [
        $vec:expr;
        $((i $is:literal $(, $iarg:expr)*)),*
        $((e $e:expr))?
    ] => {
        {
            $($vec.push(Resp::Info(format!($is, $($iarg),*))));*
            $(
                $vec.push(Resp::Error(Box::new($e.into())));
                return $vec;
            )?
        }
    };
    [ $vec:expr; (j $res:expr) ] => {
        {
            $vec.append(&mut $res);
            if let Some(Resp::Error(_)) = $vec.last() {
                return $vec;
            }
        }
    };
    [ $vec:expr; q ] => {
        {
            $vec.push(Resp::Quit);
            return $vec;
        }
    };
}

#[macro_export]
macro_rules! cli_try {
    [$e:expr] => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                return vec![Resp::Error(Box::new(err.into()))];
            }
        }
    };
    [$vec:expr; $e:expr] => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                cli_res!($vec; (e err));
            }
        }
    };
}

fn custom_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "{} {} {} {:#?}:{:#?} {} {}",
        now.now().month(),
        now.now().day(),
        now.now().time(),
        record.file().unwrap_or_else(|| "unknown file"),
        record.line().unwrap_or_else(|| 0),
        record.level(),
        record.args()
    )
}

impl Cli {
    #[allow(unwrap_check)]
    pub fn new(features: Features) -> Self {
        let base_name = "tcli";
        let suffix = "log";
        if let Ok(logger) = Logger::try_with_str("debug") {
            if let Err(err) = logger
                .log_to_file(
                    FileSpec::default()
                        .basename(base_name)
                        .suppress_timestamp()
                        .suffix(suffix),
                )
                .format(custom_format)
                .write_mode(WriteMode::BufferAndFlush)
                .use_utc()
                .start()
            {
                error!("{}", err);
            }
        }

        let (sender, resp) = mpsc::channel();

        let telio = Device::new(
            features,
            move |e: Box<DevEvent>| sender.send(Resp::Event(e)).unwrap(),
            None,
        )
        .unwrap();

        Cli {
            telio,
            resp,
            auth: None,
            nord: None,
            conf: None,
            derp_client: DerpClient::new(),
        }
    }

    pub fn exec(&mut self, cmd: &str) -> Vec<Resp> {
        let mut res = Vec::new();
        let mut args = cli_try![shellwords::split(cmd)];
        args.insert(0, "tcli".to_owned());

        match Cmd::try_parse_from(&args) {
            Ok(cmd) => cli_res!(res; (j self.exec_cmd(cmd))),
            Err(err) => {
                if err.kind() == clap::ErrorKind::DisplayHelp {
                    cli_res!(res; (i "{}", err));
                } else {
                    cli_res!(res; (e Error::Parser(err.kind())));
                }
            }
        }
        res
    }

    fn exec_cmd(&mut self, cmd: Cmd) -> Vec<Resp> {
        let mut res = Vec::new();
        match cmd {
            Cmd::Status(cmd) => cli_res!(res; (j self.report(cmd))),
            Cmd::Login(cmd) => cli_res!(res; (j self.exec_login(cmd))),
            Cmd::Events => cli_res!(res; (j self.resp.try_iter().collect())),
            Cmd::Dev(cmd) => cli_res!(res; (j self.exec_dev(cmd))),
            Cmd::Vpn(cmd) => cli_res!(res; (j self.exec_vpn(cmd))),
            Cmd::Mesh(cmd) => cli_res!(res; (j self.exec_mesh(cmd))),
            Cmd::Dns(cmd) => cli_res!(res; (j self.exec_dns(cmd))),
            Cmd::Nat(cmd) => cli_res!(res; (j self.exec_nat_detect(cmd))),
            Cmd::Derp(cmd) => cli_res!(res; (j self.derp_client.exec_cmd(cmd))),
            Cmd::Quit => cli_res!(res; q),
        }
        res
    }

    fn exec_login(&mut self, cmd: LoginCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use LoginCmd::*;
        match cmd {
            Oauth => {
                if let Some(auth) = self.auth.take() {
                    self.nord = Some(cli_try!(res; Nord::finish_login(auth)));
                    cli_res!(res; (i "logged in."))
                } else {
                    let auth = cli_try!(res; Nord::start_login());
                    cli_res!(res;
                        (i "go to: {}", &auth.redirect_uri),
                        (i "after rerun the same command again")
                    );
                    self.auth = Some(auth);
                }
            }
            Password { username, password } => {
                self.nord = Some(cli_try!(res; Nord::login(&username, &password)));
            }
            Token { token } => {
                self.nord = Some(cli_try!(res; Nord::token_login(&token)));
            }
        }
        res
    }

    fn exec_dev(&mut self, cmd: DevCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use DevCmd::*;
        match cmd {
            Start {
                adapter,
                name,
                private_key,
            } => {
                let adapter = match adapter.as_ref() {
                    "boringtun" => AdapterType::BoringTun,
                    "wireguard-go" => AdapterType::WireguardGo,
                    "linux-native" => AdapterType::LinuxNativeWg,
                    "wireguard-nt" => AdapterType::WindowsNativeWg,
                    "" => AdapterType::default(),
                    _ => unreachable!(),
                };

                let private_key = cli_try!(res; private_key
                    .or_else(|| self.nord.as_ref().map(|n| n.get_private_key())).ok_or(Error::NeedsLogin));

                cli_try!(res; self.start_telio(name, private_key, adapter, &mut res));
            }
            Con {
                public_key,
                endpoint,
                allowed_ips,
            } => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }
                let node = ExitNode {
                    public_key,
                    endpoint,
                    allowed_ips: if allowed_ips.is_empty() {
                        None
                    } else {
                        Some(allowed_ips)
                    },
                };
                cli_res!(res; (i "connecting to node:\n{:#?}", node));
                cli_try!(res; self.telio.connect_exit_node(&node));
            }
            Dis { public_key } => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }

                cli_res!(res; (i "stopping peer {}", public_key));
                cli_try!(self.telio.disconnect_exit_node(&public_key));
            }
            Disall => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }

                cli_res!(res; (i "stopping all peers"));
                cli_try!(self.telio.disconnect_exit_nodes());
            }
            NotifyNetChange => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }

                cli_res!(res; (i "notify net change"));
                cli_try!(self.telio.notify_network_change());
            }
            Stop => {
                self.telio.stop();
                cli_res!(res; (i "stopped telio."));
            }
        }
        res
    }

    fn exec_vpn(&mut self, cmd: VpnCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use VpnCmd::*;
        match cmd {
            On => {
                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));
                let server = cli_try!(res; nord.find_server());
                if !self.telio.is_running() {
                    let adapter = if cfg!(windows) {
                        // TODO: Use "wireguard-nt" as default later
                        "wireguard-go"
                    } else {
                        "boringtun"
                    };
                    cli_res!(res; (j self.exec_dev(DevCmd::Start {
                        adapter: adapter.to_owned(),
                        private_key: None,
                        name: DEFAULT_TUNNEL_NAME.to_owned(),
                    })));
                }
                cli_try!(self.telio.connect_exit_node(&server));
            }
            Off => {
                cli_try!(self.telio.disconnect_exit_nodes());
            }
        }
        res
    }

    #[allow(unwrap_check)]
    fn exec_mesh(&mut self, cmd: MeshCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use MeshCmd::*;
        match cmd {
            On { name } => {
                let conf = if let Some(conf) = self.conf.as_ref().cloned() {
                    conf
                } else {
                    cli_res!(res; (j self.exec_mesh(Register { name: name.clone() })));
                    self.conf.as_ref().cloned().unwrap()
                };

                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));
                let meshmap_str = cli_try!(res; nord.get_meshmap(&conf.id));
                cli_res!(res; (i "got config:\n{}", &meshmap_str));
                let meshmap: MeshMap = cli_try!(res; serde_json::from_str(&meshmap_str));

                let private_key = conf.sk;
                cli_try!(res; self.start_telio(name, private_key, AdapterType::default(), &mut res));
                cli_try!(res; self.telio.set_config(&Some(meshmap)));
                cli_res!(res; (i "started meshnet"));
            }
            Register { name } => {
                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));

                let mut base_dir = dirs::data_local_dir().unwrap();
                base_dir.push("tcli");

                if !base_dir.exists() {
                    fs::create_dir_all(&base_dir).unwrap();
                }
                base_dir.push(&format!("{}.json", name));
                let conf = if let Some(conf) = self.conf.as_ref().cloned() {
                    cli_res!(res; (i "using chached config."));
                    conf
                } else if let Ok(config_file) = fs::File::open(&base_dir) {
                    let conf: MeshConf = cli_try!(res; serde_json::from_reader(config_file));
                    cli_res!(res; (i "found existing config."));
                    conf
                } else {
                    let sk = SecretKey::gen();
                    let pk = sk.public();
                    let id = cli_try!(res; nord.register(&name, &pk));
                    let conf = MeshConf { name, sk, pk, id };
                    let mut file = fs::File::create(&base_dir).unwrap();
                    cli_try!(res; serde_json::to_writer(&mut file, &conf));
                    cli_res!(res; (i "registered new device."));
                    conf
                };
                self.conf = Some(conf);
            }
            Ping {} => {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 5000)).await {
                        Ok(udp_socket) => {
                            let udp_socket = Arc::new(udp_socket);

                    // Timeout for stunner
                    let sleep = sleep(Duration::from_secs(20));
                    tokio::pin!(sleep);
                    // let socket = udp_socket.clone();
                    const MAX_PACKET: usize = 65536;
                    let mut rx_buff = [0u8; MAX_PACKET];
                    loop {
                        tokio::select! {
                                Ok((len, _src_addr)) = udp_socket.recv_from(&mut rx_buff) => {
                                    match Packet::decode(&rx_buff[..len]) {
                                        Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                           // Check if message is PING or PONG type
                                           if pinger_msg.get_message_type() == PingType::PING {
                                               cli_res!(res; (i "Pinger message received"));
                                           } else if pinger_msg.get_message_type() == PingType::PONG {
                                               cli_res!(res; (i "Ponger message received"));
                                           }
                                           break;
                                        }
                                        Err(err) => {
                                             cli_res!(res; (i "Error parsing PingerMsgDeprecated {}", err));
                                             break;
                                        }
                                        _ => {}
                                    }
                                },

                                () = &mut sleep => {
                                    cli_res!(res; (i "timeout"));
                                    break;
                                },

                        }
                    }
                        }
                        Err(_) => {
                            cli_res!(res; (i "udp socket init error"));
                        }
                    }
                })
            }
            // Stunner test
            Stun {} => {
                let servers_config = self.telio.get_derp_config().unwrap();

                let rt = Runtime::new().unwrap();

                rt.block_on(async {
                    let spool = SocketPool::default();
                    match spool.new_external_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), None).await {
                        Ok(udp_socket) => {
                            let udp_socket = Arc::new(udp_socket);

                            let (stunner, packet_tx) = Stunner::start(
                                udp_socket.clone(),
                                Some(StunConfig {
                                        plain_text_fallback: true,
                                        servers: servers_config,
                                    })
                                );

                            // SocketRx -> Stunner forwarder
                            let mut forwarder = tokio::spawn(async move {
                                const MAX_PACKET: usize = 65536;
                                let mut rx_buff = [0u8; MAX_PACKET];

                                while let Ok((len, src_addr)) =
                                    udp_socket.recv_from(&mut rx_buff).await
                                {
                                    #[allow(mpsc_blocking_send)]
                                    if let Err(_) =
                                        packet_tx.send((rx_buff[..len].to_vec(), src_addr)).await
                                    {
                                        return;
                                    }
                                }
                            });

                            let mut fetcher = tokio::spawn(async move {
                                let _ = stunner.do_stun().await;

                                loop {
                                    sleep(Duration::from_secs(1)).await;

                                    if let Ok(endpoints) = stunner.fetch_endpoints().await {
                                        return Ok(endpoints);
                                    }
                                }

                                #[allow(unreachable_code)]
                                Err(())
                            });

                            // Timeout for stunner
                            let sleep = sleep(Duration::from_secs(60));
                            tokio::pin!(sleep);

                            loop {
                                tokio::select! {
                                    () = &mut sleep => {
                                        cli_res!(res; (i "timeout"));
                                        break;
                                    },
                                    Ok(()) = &mut forwarder => {
                                        break;
                                    },
                                    Ok(endpoints) = &mut fetcher => {
                                        cli_res!(res; (i "got endpoints: {:?}", endpoints.unwrap().to_vec().unwrap()));
                                        break;
                                    }
                                };
                            }
                        }
                        Err(_) => cli_res!(res; (i "udp socket init error")),
                    }
                });
            }
            Config { mesh_config } => {
                let meshmap: MeshMap = cli_try!(serde_json::from_str(&mesh_config));
                cli_try!(self.telio.set_config(&Some(meshmap)));
            }
            Off => {
                cli_try!(res; self.telio.set_config(&None));
            }
        }

        res
    }

    fn exec_dns(&mut self, cmd: DnsCmd) -> Vec<Resp> {
        let mut res = Vec::new();

        match cmd {
            DnsCmd::On { forward_servers } => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }

                let forward_servers: Vec<IpAddr> = forward_servers
                    .iter()
                    .filter_map(|server| server.parse().ok())
                    .collect();

                cli_res!(res; (i "starting magic dns with forward servers: {:?}...", forward_servers));
                cli_try!(res; self.telio.enable_magic_dns(&forward_servers));
            }
            DnsCmd::Off => {
                cli_try!(res; self.telio.disable_magic_dns());
            }
        }

        res
    }

    fn exec_nat_detect(&mut self, cmd: DetectCmd) -> Vec<Resp> {
        let mut res = Vec::new();

        match cmd {
            DetectCmd::Address { stun_server } => match self.telio.get_nat(stun_server) {
                Ok(data) => {
                    cli_res!(res; (i"Public Address: {:?}", data.public_ip));
                    cli_res!(res; (i"Nat Type: {:?}", data.nat_type));
                }

                Err(error) => {
                    cli_res!(res; (i"problem: {}", error));
                }
            },
        }

        res
    }

    fn start_telio(
        &mut self,
        name: String,
        private_key: SecretKey,
        adapter_type: AdapterType,
        res: &mut Vec<Resp>,
    ) -> Result<(), Error> {
        if !self.telio.is_running() {
            let device_config = DeviceConfig {
                private_key,
                name: Some(name.clone()),
                adapter: adapter_type,
                ..Default::default()
            };

            self.telio.start(&device_config)?;

            #[cfg(target_os = "linux")]
            let _ = self.telio.set_fwmark(FWMARK_VALUE)?;

            cli_res!(res; (i "started telio with {:?}:{}...", adapter_type, private_key));
        }
        Ok(())
    }
}

impl Report for Cli {
    #[allow(unwrap_check)]
    fn report(&self, cmd: StatusCmd) -> Vec<Resp> {
        use StatusCmd::*;
        let mut res = Vec::new();
        if let Some(ref nord) = self.nord {
            cli_res!(res; (i "logged in as {}.", nord.user))
        } else {
            cli_res!(res; (i "no login."))
        }

        if self.telio.is_running() {
            match cmd {
                Simple => {
                    cli_res!(res;
                        (i "telio running."),
                        (i "telio nodes: {}", serde_json::to_string(&self.telio.nodes().unwrap()).unwrap()),
                        (i "derp status: {}", serde_json::to_string(&self.telio.get_derp_server().unwrap()).unwrap())
                    );
                }
                Pretty => {
                    cli_res!(res;
                        (i "telio running."),
                        (i "telio nodes:\n{}", serde_json::to_string_pretty(&self.telio.nodes().unwrap()).unwrap()),
                        (i "derp status:\n{}", serde_json::to_string_pretty(&self.telio.get_derp_server().unwrap()).unwrap())
                    );
                }
            }
        } else {
            cli_res!(res; (i "stopped."));
        }
        res
    }
}
