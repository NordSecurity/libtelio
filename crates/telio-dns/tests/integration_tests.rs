use base64::encode;
use boringtun::{crypto::x25519::X25519SecretKey, noise::Tunn};
use std::{
    fmt,
    fs::{remove_file, write},
    io,
    net::{IpAddr, Ipv4Addr},
    process::Command,
    sync::Arc,
};
use telio_dns::{LocalNameServer, NameServer, Records};
use tokio::net::UdpSocket;

/// Wireguard key pair.
struct KeyPair {
    private: String,
    public: String,
}

impl KeyPair {
    /// Generate WireGuard key pair.
    fn new() -> Self {
        let private_key = X25519SecretKey::new();
        let public_key = private_key.public_key();
        KeyPair {
            private: encode(private_key.as_bytes()),
            public: encode(public_key.as_bytes()),
        }
    }
}

/// Config is in INI format.
struct WireguardConfig {
    private_key: String,
    peer_public_key: String,
    local_address: String,
    peer_address: String,
}

impl WireguardConfig {
    fn new(private_key: &str, peer_key: &str, local_address: &str, peer_address: &str) -> Self {
        WireguardConfig {
            private_key: private_key.to_owned(),
            peer_public_key: peer_key.to_owned(),
            local_address: local_address.to_owned(),
            peer_address: peer_address.to_owned(),
        }
    }
}

impl fmt::Display for WireguardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"[Interface] # Regular peer
                PrivateKey = {}
                Address = {}
                ListenPort = 51820

                [Peer] # DNS resolver
                PublicKey = {}
                Endpoint = 127.0.0.1:51821
                AllowedIPs = {}
                "#,
            self.private_key, self.local_address, self.peer_public_key, self.peer_address,
        )
    }
}

/// Wireguard kernel module implementation.
struct WireguardKernel {
    config_file: String,
}

impl WireguardKernel {
    fn new(
        private_key: &str,
        peer_key: &str,
        local_address: &str,
        peer_address: &str,
    ) -> Result<Self, io::Error> {
        let config_file = "/tmp/main.conf";
        let config = WireguardConfig::new(private_key, peer_key, local_address, peer_address);
        write(config_file, config.to_string().as_bytes())?;

        Command::new("wg-quick")
            .args(&["up", config_file])
            .status()?;

        Ok(WireguardKernel {
            config_file: config_file.to_owned(),
        })
    }
}

impl Drop for WireguardKernel {
    fn drop(&mut self) {
        Command::new("wg-quick")
            .args(&["down", &self.config_file])
            .status()
            .expect("failed to stop wireguard");
        remove_file(&self.config_file).expect("failed to remove wireguard config");
    }
}

fn drill(nameserver: &str, host: &str) -> String {
    let response = String::from_utf8(
        Command::new("drill")
            .args(&[format!("@{}", nameserver), host.to_owned()])
            .output()
            .expect("drill is not installed")
            .stdout,
    )
    .expect("no response from the nameserver");

    response
}

#[ignore] // does not work in CI
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn dns_over_wireguard() {
    // Test the connection between WireGuard kernel module and
    // the local peer providing DNS server over WireGuard protocol.
    let kernel_keys = KeyPair::new();
    let kernel_address = String::from("100.100.100.101/32");
    let dns_address = String::from("100.100.100.102/32");
    let dns_keys = KeyPair::new();

    let _stock_wireguard = WireguardKernel::new(
        &kernel_keys.private,
        &dns_keys.public,
        &kernel_address,
        &dns_address,
    );

    let mut records = Records::new();
    records.insert(
        String::from("alice.nord"),
        vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 123))],
    );
    let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
        .await
        .unwrap();
    nameserver.upsert("nord", &records).await.unwrap();

    let dns_socket = Arc::new(UdpSocket::bind("127.0.0.1:51821").await.unwrap());
    let dns_wireguard = Arc::from(
        Tunn::new(
            Arc::new(dns_keys.private.parse().unwrap()),
            Arc::new(kernel_keys.public.parse().unwrap()),
            None,
            None,
            0,
            None,
        )
        .unwrap(),
    );

    nameserver
        .start(
            dns_wireguard,
            dns_socket,
            "127.0.0.1:51820".parse().unwrap(),
        )
        .await;

    records.insert(
        String::from("bob.nord"),
        vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 213))],
    );

    nameserver.upsert("nord", &records).await.unwrap();

    assert!(drill("100.100.100.102", "bob.nord").contains("100.64.0.213"));
}
