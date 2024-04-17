use boringtun::noise::Tunn;
use std::{
    fmt,
    fs::{remove_file, write},
    io,
    net::{IpAddr, Ipv4Addr},
    process::Command,
    sync::Arc,
};
use telio_crypto::{PublicKey, SecretKey};
use telio_dns::{LocalNameServer, NameServer, Records};
use telio_model::features::TtlValue;
use tokio::{net::UdpSocket, sync::Mutex};
use x25519_dalek::{PublicKey as PublicDalek, StaticSecret};

/// Config is in INI format.
struct WireguardConfig {
    private_key: SecretKey,
    peer_public_key: PublicKey,
    local_address: String,
    peer_address: String,
}

impl WireguardConfig {
    fn new(
        private_key: &SecretKey,
        peer_key: &PublicKey,
        local_address: &str,
        peer_address: &str,
    ) -> Self {
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
        private_key: &SecretKey,
        peer_key: &PublicKey,
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
    let kernel_privatekey = SecretKey::gen();
    let kernel_address = String::from("100.100.100.101/32");
    let dns_address = String::from("100.100.100.102/32");
    let private_key = SecretKey::gen();
    let public_key = PublicKey::from(&private_key);

    let _stock_wireguard = WireguardKernel::new(
        &kernel_privatekey,
        &public_key,
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
    nameserver
        .upsert("nord", &records, TtlValue(60))
        .await
        .unwrap();

    let dns_socket = Arc::new(UdpSocket::bind("127.0.0.1:51821").await.unwrap());
    let dns_wireguard = Arc::new(Mutex::new(
        Tunn::new(
            StaticSecret::from(private_key.into_bytes()),
            PublicDalek::from(public_key.0),
            None,
            None,
            0,
            None,
        )
        .unwrap(),
    ));

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

    nameserver
        .upsert("nord", &records, TtlValue(60))
        .await
        .unwrap();

    assert!(drill("100.100.100.102", "bob.nord").contains("100.64.0.213"));
}
