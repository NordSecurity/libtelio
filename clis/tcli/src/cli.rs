use crate::derp::{DerpClient, DerpClientCmd};
use clap::Parser;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use telio::crypto::{PublicKey, SecretKey};
use telio::device::{Device, DeviceConfig};
use telio_model::config::{RelayState, Server};
use telio_model::features::Features;
use telio_model::{config::Config as MeshMap, event::Event as DevEvent, mesh::ExitNode};
use telio_proto::CodecError;
#[cfg(target_os = "linux")]
use telio_utils::LIBTELIO_FWMARK;
use telio_wg::AdapterType;
use thiserror::Error;
use tracing::error;

use crate::nord::{Error as NordError, Nord, OAuth};

use std::fmt::Display;
use std::str::FromStr;
use std::time::SystemTime;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
};

#[cfg(windows)]
const DEFAULT_TUNNEL_NAME: &str = "NordLynx";

#[cfg(target_os = "linux")]
const DEFAULT_TUNNEL_NAME: &str = "nlx0";

#[cfg(target_os = "macos")]
const DEFAULT_TUNNEL_NAME: &str = "utun10";

#[derive(Debug, Error)]
pub enum Error {
    #[error("device must be started.")]
    NotStarted,

    #[error("meshnet must be started.")]
    MeshnetNotStarted,

    #[error("login is needed.")]
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

    #[error("bad command: {0:?}.")]
    Parser(clap::error::ErrorKind),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Codec(#[from] CodecError),

    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Apple(#[from] telio_sockets::protector::platform::Error),

    #[error("config is empty.")]
    EmptyConfig,

    #[error("data local dir unknown.")]
    NoDataLocalDir,

    #[error(transparent)]
    KeyDecodeError(#[from] telio_crypto::KeyDecodeError),

    #[error(transparent)]
    WgAdapterError(#[from] telio_wg::Error),

    #[error("setting ip address for the adapter failed.")]
    SettingIpFailed,
}

pub struct Cli {
    telio: Device,
    resp: Receiver<Resp>,
    auth: Option<OAuth>,
    nord: Option<Nord>,
    conf: Option<MeshConf>,
    meshmap: Option<MeshMap>,
    derp_client: DerpClient,
    derp_server: Arc<Mutex<Option<Server>>>,
}

#[derive(Debug)]
pub enum Resp {
    Info(String),
    Event {
        ts: SystemTime,
        event: Box<DevEvent>,
    },
    Error(Box<Error>),
    Quit,
}

impl Display for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resp::Info(msg) => {
                write!(f, "INFO: {}", msg)
            }
            Resp::Error(e) => {
                write!(f, "ERROR: {:?}", e)
            }
            Resp::Quit => {
                write!(f, "QUIT")
            }
            Resp::Event { ts, event } => {
                write!(f, "EVENT: {:?}:{:?}", ts, event)
            }
        }
    }
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
    #[clap(about = "Status about telio, nodes, derp")]
    Status,
    #[clap(about = "Same as 'status' but in json string")]
    StatusSimple,
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
    Derp(DerpClientCmd),
    Quit,
}

enum StatusCmd {
    Simple,
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
        #[clap(value_parser = ["neptun", "wireguard-nt", "linux-native", ""], default_value ="")]
        adapter: String,
        /// Name of device
        #[clap(default_value = DEFAULT_TUNNEL_NAME)]
        name: String,
        /// Specify private_key to use instead of one provided from login
        private_key: Option<SecretKey>,
    },
    #[clap(about = "Connect to node")]
    Con {
        /// Public key of node
        public_key: PublicKey,
        /// IP:PORT of Endpoint. Must be specified for a regular VPN server. Not needed for a peer.
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<IpNet>,
        /// Turns on the post-quantum tunnel
        #[clap(long = "pq")]
        postquantum: bool,
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
    #[clap(about = "Trigger analytics event")]
    Analytics,
    #[clap(about = "Trigger qos collection")]
    Qos,
}

#[derive(Parser)]
enum VpnCmd {
    #[clap(about = "Connect to vpn server.")]
    On {
        /// Turns on the post-quantum tunnel
        #[clap(long = "pq")]
        postquantum: bool,
    },
    #[clap(about = "Disconnect from vpn server.")]
    Off,
    #[clap(about = "Set 10.5.0.2 address for the adapter")]
    SetIp {
        #[clap(default_value = DEFAULT_TUNNEL_NAME)]
        name: String,
    },
}

#[derive(Parser)]
enum MeshCmd {
    /// Turn mesnet on
    On {
        name: String,
        #[clap(value_parser = ["neptun", "wireguard-nt", "linux-native", ""], default_value ="")]
        adapter: String,
    },
    /// Set own meshnet ip address for the adapter
    SetIp {
        /// Name of device. By default the one used in 'on' command
        #[clap(default_value = "")]
        name: String,
    },
    /// Register to mesh as with some name
    Register {
        name: String,
    },
    ///Pinger test
    Ping {},
    /// Manually set json config. If MESH_CONFIG is empty it will print current config
    Config {
        #[clap(default_value = "")]
        mesh_config: String,
    },
    /// Read meshmap from file
    FileConfig {
        filename: std::path::PathBuf,
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

impl Cli {
    pub fn new(
        features: Features,
        token: Option<String>,
        derp_server: Arc<Mutex<Option<Server>>>,
    ) -> anyhow::Result<Self> {
        let (sender, resp) = mpsc::channel();

        let derp_server_lambda = derp_server.clone();
        let telio = Device::new(
            features,
            {
                let sender = sender.clone();
                #[allow(clippy::unwrap_used)]
                move |event: Box<DevEvent>| {
                    let ts = SystemTime::now();

                    if let DevEvent::Relay { body } = &*event {
                        *derp_server_lambda.lock() = if body.conn_state != RelayState::Disconnected
                        {
                            Some(body.clone())
                        } else {
                            None
                        }
                    }
                    sender.send(Resp::Event { ts, event }).unwrap()
                }
            },
            None,
        )?;

        let nord = if let Some(token) = token {
            match Nord::token_login(&token) {
                Ok(nord) => {
                    sender.send(Resp::Info("Logged in using NORD_TOKEN".to_string()))?;
                    Some(nord)
                }
                Err(_) => {
                    sender.send(Resp::Info("Failed to log in using NORD_TOKEN".to_string()))?;
                    None
                }
            }
        } else {
            None
        };

        Ok(Cli {
            telio,
            resp,
            auth: None,
            nord,
            conf: None,
            meshmap: None,
            derp_client: DerpClient::new(),
            derp_server,
        })
    }

    pub fn exec(&mut self, cmd: &str) -> Vec<Resp> {
        let mut res = Vec::new();
        let mut args = cli_try![shellwords::split(cmd)];
        args.insert(0, "tcli".to_owned());

        let parse_try_result = Cmd::try_parse_from(&args);
        match parse_try_result {
            Ok(cmd) => cli_res!(res; (j self.exec_cmd(cmd))),
            Err(err) => {
                cli_res!(res; (i "{}", err));
            }
        }
        res
    }

    fn exec_cmd(&mut self, cmd: Cmd) -> Vec<Resp> {
        let mut res = Vec::new();
        match cmd {
            Cmd::Status => cli_res!(res; (j self.report(StatusCmd::Pretty))),
            Cmd::StatusSimple => cli_res!(res; (j self.report(StatusCmd::Simple))),
            Cmd::Login(cmd) => cli_res!(res; (j self.exec_login(cmd))),
            Cmd::Events => cli_res!(res; (j self.resp.try_iter().collect())),
            Cmd::Dev(cmd) => cli_res!(res; (j self.exec_dev(cmd))),
            Cmd::Vpn(cmd) => cli_res!(res; (j self.exec_vpn(cmd))),
            Cmd::Mesh(cmd) => cli_res!(res; (j self.exec_mesh(cmd))),
            Cmd::Dns(cmd) => cli_res!(res; (j self.exec_dns(cmd))),
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
                let adapter = cli_try!(res; AdapterType::from_str(&adapter));

                let private_key = cli_try!(res; private_key
                    .or_else(|| self.nord.as_ref().and_then(|n| n.get_private_key().ok())).ok_or(Error::NeedsLogin));

                cli_try!(res; self.start_telio(name, private_key, adapter, &mut res));
            }
            Con {
                public_key,
                endpoint,
                allowed_ips,
                postquantum,
            } => {
                if !self.telio.is_running() {
                    cli_res!(res; (e Error::NotStarted));
                }
                let node = ExitNode {
                    identifier: "tcli".to_owned(),
                    public_key,
                    endpoint,
                    allowed_ips: if allowed_ips.is_empty() {
                        None
                    } else {
                        Some(allowed_ips)
                    },
                };

                if postquantum {
                    cli_res!(res; (i "connecting to PQ node:\n{:#?}", node));
                    cli_try!(res; self.telio.connect_vpn_post_quantum(&node));
                } else {
                    cli_res!(res; (i "connecting to node:\n{:#?}", node));
                    cli_try!(res; self.telio.connect_exit_node(&node));
                }
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
            Analytics => {
                cli_res!(res; (i "Trigger analytics event."));
                cli_try!(self.telio.trigger_analytics_event());
            }
            Qos => {
                cli_res!(res; (i "Trigger qos collection."));
                cli_try!(self.telio.trigger_qos_collection());
            }
        }
        res
    }

    fn exec_vpn(&mut self, cmd: VpnCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use VpnCmd::*;
        match cmd {
            On { postquantum } => {
                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));
                let server = cli_try!(res; nord.find_server());
                if !self.telio.is_running() {
                    let adapter = if cfg!(windows) {
                        "wireguard-nt"
                    } else {
                        "neptun"
                    };
                    cli_res!(res; (j self.exec_dev(DevCmd::Start {
                        adapter: adapter.to_owned(),
                        private_key: None,
                        name: DEFAULT_TUNNEL_NAME.to_owned(),
                    })));
                }

                if postquantum {
                    cli_try!(self.telio.connect_vpn_post_quantum(&server));
                } else {
                    cli_try!(self.telio.connect_exit_node(&server));
                }
            }
            SetIp { name } => {
                cli_try!(self.set_ip(&name, "10.5.0.2/16"));
            }
            Off => {
                cli_try!(self.telio.disconnect_exit_nodes());
            }
        }
        res
    }

    #[allow(clippy::indexing_slicing)]
    fn exec_mesh(&mut self, cmd: MeshCmd) -> Vec<Resp> {
        let mut res = Vec::new();
        use MeshCmd::*;
        match cmd {
            On { name, adapter } => {
                let conf = if let Some(conf) = self.conf.as_ref().cloned() {
                    conf
                } else {
                    cli_res!(res; (j self.exec_mesh(Register { name: name.clone() })));
                    cli_try!(self.conf.as_ref().cloned().ok_or(Error::EmptyConfig))
                };

                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));
                let meshmap_str = cli_try!(res; nord.get_meshmap(&conf.id));
                cli_res!(res; (i "got config:\n{}", &meshmap_str));
                self.meshmap = cli_try!(res; serde_json::from_str(&meshmap_str));
                let adapter_type = cli_try!(res; AdapterType::from_str(&adapter));

                let private_key = conf.sk;
                cli_try!(res; self.start_telio(name, private_key, adapter_type, &mut res));
                cli_try!(res; self.telio.set_config(&self.meshmap));
                cli_res!(res; (i "started meshnet"));
            }
            SetIp { mut name } => {
                let meshmap = cli_try!(self
                    .meshmap
                    .as_ref()
                    .cloned()
                    .ok_or(Error::MeshnetNotStarted));
                if name.is_empty() {
                    let config =
                        cli_try!(self.conf.as_ref().cloned().ok_or(Error::MeshnetNotStarted));
                    name = config.name;
                }

                let ip_addr = meshmap.ip_addresses.as_ref().cloned().unwrap_or_default();
                if ip_addr.len() != 1 {
                    cli_res!(res; (e Error::SettingIpFailed));
                }

                let ip_addr =
                    ip_addr[0].to_string() + if ip_addr[0].is_ipv4() { "/10" } else { "/64" };

                cli_try!(self.set_ip(&name, &ip_addr));
            }
            Register { name } => {
                let nord = cli_try!(res; self.nord.as_ref().ok_or(Error::NeedsLogin));

                let mut base_dir =
                    cli_try!(res; dirs::data_local_dir().ok_or(Error::NoDataLocalDir));
                base_dir.push("tcli");

                if !base_dir.exists() {
                    cli_try!(res; fs::create_dir_all(&base_dir));
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
                    let mut file = cli_try!(res; fs::File::create(&base_dir));
                    cli_try!(res; serde_json::to_writer(&mut file, &conf));
                    cli_res!(res; (i "registered new device."));
                    conf
                };
                self.conf = Some(conf);
            }
            Ping {} => cli_res!(res; (i "receive ping - {:?}", self.telio.receive_ping())),
            Config { mesh_config } => {
                if mesh_config.is_empty() {
                    let meshmap =
                        cli_try!(self.meshmap.as_ref().cloned().ok_or(Error::EmptyConfig));
                    let meshmap = cli_try!(serde_json::to_string_pretty(&meshmap));
                    cli_res!(res; (i "Current meshnet config:\n{}", meshmap));
                } else {
                    let meshmap: MeshMap = cli_try!(serde_json::from_str(&mesh_config));
                    cli_try!(self.telio.set_config(&Some(meshmap)));
                }
            }
            FileConfig { filename } => {
                let file_contents = cli_try!(fs::read_to_string(filename));
                let meshmap: MeshMap = cli_try!(serde_json::from_str(&file_contents));
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

    fn start_telio(
        &mut self,
        name: String,
        private_key: SecretKey,
        adapter_type: AdapterType,
        res: &mut Vec<Resp>,
    ) -> Result<(), Error> {
        if !self.telio.is_running() {
            let device_config = DeviceConfig {
                private_key: private_key.clone(),
                name: Some(name),
                adapter: adapter_type.clone(),
                ..Default::default()
            };

            self.telio.start(device_config)?;

            #[cfg(target_os = "linux")]
            self.telio.set_fwmark(LIBTELIO_FWMARK)?;

            cli_res!(res; (i "started telio with {:?}:{:?}...", adapter_type, private_key));
        }
        Ok(())
    }

    fn set_ip(&self, adapter_name: &str, ip_address: &str) -> Result<(), Error> {
        let execute = |command: &mut Command| -> Result<(), Error> {
            command
                .output()
                .map_err(|_| Error::SettingIpFailed)
                .and_then(|r| {
                    if r.status.success() {
                        Ok(())
                    } else {
                        error!("Error executing command {:?}: {:?}", command, r);
                        Err(Error::SettingIpFailed)
                    }
                })
        };

        let ip: IpNet = match ip_address.parse() {
            Ok(ip) => ip,
            Err(_) => return Err(Error::SettingIpFailed),
        };

        if std::env::consts::OS == "windows" {
            let mut args = vec![
                "interface",
                if ip.addr().is_ipv4() { "ipv4" } else { "ipv6" },
                "set",
                "address",
                adapter_name,
            ];
            if ip.addr().is_ipv4() {
                args.push("static");
            }
            args.push(ip_address);
            execute(Command::new("netsh").args(args))
        } else if std::env::consts::OS == "macos" {
            let len = ip_address.len();
            if len < 3 {
                return Err(Error::SettingIpFailed);
            }

            let result = execute(Command::new("ifconfig").args([
                adapter_name,
                if ip.addr().is_ipv4() { "inet" } else { "inet6" },
                ip_address,
                ip.addr().to_string().as_ref(),
            ]));

            // Add route for meshnet
            if result.is_ok() {
                if ip.addr().is_ipv4() {
                    return execute(Command::new("route").args([
                        "add",
                        "100.64/10",
                        ip.addr().to_string().as_ref(),
                    ]));
                } else {
                    return execute(Command::new("route").args([
                        "add",
                        "-inet6",
                        "fd74:656c:696f::/64",
                        ip.addr().to_string().as_ref(),
                    ]));
                }
            } else {
                return result;
            }
        } else {
            execute(Command::new("ifconfig").args([
                adapter_name,
                if ip.addr().is_ipv4() { "inet" } else { "inet6" },
                ip_address,
            ]))?;
            execute(Command::new("ifconfig").args([adapter_name, "up"]))
        }
    }

    fn report(&self, cmd: StatusCmd) -> Vec<Resp> {
        use StatusCmd::*;
        let mut res = Vec::new();
        if let Some(ref nord) = self.nord {
            cli_res!(res; (i "logged in as {}.", nord.user))
        } else {
            cli_res!(res; (i "no login."))
        }

        if self.telio.is_running() {
            let telio_nodes = cli_try!(res; self.telio.external_nodes());
            let derp_status = (*self.derp_server.lock()).clone();
            match cmd {
                Simple => {
                    let telio_nodes = cli_try!(res; serde_json::to_string(&telio_nodes));
                    let derp_status = cli_try!(res; serde_json::to_string(&derp_status));
                    cli_res!(res;
                        (i "telio running."),
                        (i "telio nodes: {}", telio_nodes),
                        (i "derp status: {}", derp_status)
                    );
                }
                Pretty => {
                    let telio_nodes = cli_try!(res; serde_json::to_string_pretty(&telio_nodes));
                    let derp_status = cli_try!(res; serde_json::to_string_pretty(&derp_status));
                    cli_res!(res;
                        (i "telio running."),
                        (i "telio nodes:\n{}", telio_nodes),
                        (i "derp status:\n{}", derp_status)
                    );
                }
            }
        } else {
            cli_res!(res; (i "stopped."));
        }
        res
    }
}
