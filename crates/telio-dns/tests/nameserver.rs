use boringtun::crypto::x25519::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};
use dns_parser::{self, Builder, QueryClass, QueryType};
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    udp::{ipv4_checksum, MutableUdpPacket, UdpPacket},
    Packet,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use telio_crypto::SecretKey;
use telio_dns::{LocalNameServer, NameServer, Records};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio::{
    self,
    time::{timeout, Duration},
};

const IP_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const MAX_PACKET: usize = 2048;

struct WGClient {
    client_socket: tokio::net::UdpSocket,
    client_address: SocketAddr,
    server_address: SocketAddr,
    tunnel: Arc<Tunn>,
}

impl WGClient {
    async fn new(
        client_secret_key: SecretKey,
        server_public_key: Arc<X25519PublicKey>,
        server_address: SocketAddr,
    ) -> Self {
        let client_socket =
            tokio::net::UdpSocket::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
                .await
                .expect("Failed to bind client socket");
        let client_port = client_socket
            .local_addr()
            .expect("Failed to get client local address")
            .port();
        let client_address = ([127, 0, 0, 1], client_port).into();
        let client_private_key: Arc<X25519SecretKey> = Arc::new(
            client_secret_key
                .to_string()
                .parse()
                .expect("Failed to convert client private key"),
        );

        WGClient {
            client_socket,
            client_address,
            server_address,
            tunnel: Arc::<Tunn>::from(
                Tunn::new(
                    client_private_key,
                    server_public_key.clone(),
                    None,
                    None,
                    0,
                    None,
                )
                .expect("Failed to create client tunnel"),
            ),
        }
    }

    async fn do_handshake(&self) {
        let mut sending_buffer = vec![0u8; MAX_PACKET];
        let mut receiving_buffer = vec![0u8; MAX_PACKET];

        match self.tunnel.encapsulate(&[], &mut sending_buffer) {
            TunnResult::WriteToNetwork(msg) => {
                self.client_socket
                    .send_to(msg, self.server_address)
                    .await
                    .expect("Failed to send handshake message");
            }
            TunnResult::Err(e) => panic!("Encapsulate error: {:?}", e),
            _ => println!("Unexpected TunnResult during handshake phase"),
        }

        let bytes_read = self
            .client_socket
            .recv(&mut receiving_buffer)
            .await
            .expect("Failed to recv from server");
        match self
            .tunnel
            .decapsulate(None, &receiving_buffer[..bytes_read], &mut sending_buffer)
        {
            TunnResult::WriteToNetwork(msg) => {
                self.client_socket
                    .send_to(msg, self.server_address)
                    .await
                    .expect("Failed to send handshake message");

                // Handshake should be completed now
            }
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult during handshake phase"),
        }
    }

    async fn send_dns_request(&self, query: &str, test_type: DnsTestType) {
        let request = WGClient::build_dns_request(query, test_type);

        let mut sending_buffer = vec![0u8; MAX_PACKET];
        let mut receiving_buffer = vec![0u8; MAX_PACKET];

        match self.tunnel.encapsulate(&request[..], &mut sending_buffer) {
            TunnResult::WriteToNetwork(msg) => {
                self.client_socket
                    .send_to(msg, self.server_address)
                    .await
                    .expect("Failed to send the dns request");
            }
            TunnResult::Err(e) => panic!("Encapsulate error: {:?}", e),
            _ => println!("Unexpected TunnResult while sending the dns request"),
        }

        let result = timeout(
            Duration::from_secs(10),
            self.client_socket.recv(&mut receiving_buffer),
        )
        .await;

        if result.is_err() {
            if !matches!(test_type, DnsTestType::Correct) {
                // A timeout is expected during "Bad" scenarios.
                // The server should ignore bad requests.
                return;
            } else {
                panic!("Didn't receive a response from the server");
            }
        } else {
            if !matches!(test_type, DnsTestType::Correct) {
                panic!("Received a response when shouldn't");
            }
        }

        let bytes_read = result.unwrap().expect("Failed to recv from server");
        match self
            .tunnel
            .decapsulate(None, &receiving_buffer[..bytes_read], &mut sending_buffer)
        {
            TunnResult::WriteToTunnelV4(response, _) => {
                let ip_response = Ipv4Packet::new(response).expect("Failed to parse ip response");
                let udp_response =
                    UdpPacket::new(ip_response.payload()).expect("Failed to parse udp response");
                dns_parser::Packet::parse(udp_response.payload())
                    .expect("Failed to parse dns response");
            }
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => println!("Unexpected TunnResult while receiving the dns response"),
        }
    }

    fn build_dns_request(query: &str, test_type: DnsTestType) -> Vec<u8> {
        let mut builder = Builder::new_query(1, true);
        builder.add_question(query, false, QueryType::A, QueryClass::IN);
        let dns_query = builder.build().expect("Failed to build the dns query");

        let length = IP_HEADER + UDP_HEADER + dns_query.len();
        let mut buffer = vec![0u8; MAX_PACKET];

        let local_address = Ipv4Addr::new(127, 0, 0, 1);

        {
            let mut ip_packet =
                MutableIpv4Packet::new(&mut buffer).expect("Failed to create MutableIpv4Packet");
            ip_packet.set_version(4);
            ip_packet.set_header_length((IP_HEADER / 4) as u8);
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(length as u16);
            ip_packet.set_flags(0);
            ip_packet.set_identification(0x9112); // Random value
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_ttl(128);
            ip_packet.set_source(local_address);
            ip_packet.set_destination(local_address);
            ip_packet.set_checksum(0);
            if !matches!(test_type, DnsTestType::BadIpChecksum) {
                ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
            }
        }

        {
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[IP_HEADER..length])
                .expect("Failed to create MutableUdpPacket");
            udp_packet.set_source(100);
            udp_packet.set_destination(54);
            if !matches!(test_type, DnsTestType::BadUdpPort) {
                udp_packet.set_destination(53);
            }
            udp_packet.set_length((UDP_HEADER + dns_query.len()) as u16);
            udp_packet.set_payload(&dns_query);
            udp_packet.set_checksum(0);
            if !matches!(test_type, DnsTestType::BadUdpChecksum) {
                udp_packet.set_checksum(ipv4_checksum(
                    &udp_packet.to_immutable(),
                    &local_address,
                    &local_address,
                ));
            }
        }

        buffer.truncate(length);
        buffer
    }

    fn client_address(&self) -> SocketAddr {
        self.client_address
    }
}

#[derive(Copy, Clone)]
enum DnsTestType {
    Correct,
    BadIpChecksum,
    BadUdpChecksum,
    BadUdpPort,
}

async fn dns_test(query: &str, test_type: DnsTestType, local_records: Option<(String, Records)>) {
    let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
        .await
        .expect("Failed to create a LocalNameServer");

    dns_test_with_server(query, test_type, local_records, nameserver).await;
}

async fn dns_test_with_server(
    query: &str,
    test_type: DnsTestType,
    local_records: Option<(String, Records)>,
    nameserver: Arc<RwLock<LocalNameServer>>,
) {
    if let Some((zone, records)) = local_records {
        nameserver
            .upsert(&zone, &records)
            .await
            .expect("Failed to upsert local records");
    }

    let server_socket = tokio::net::UdpSocket::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .expect("Failed to bind server socket");
    let server_port = server_socket
        .local_addr()
        .expect("Failed to get server local address")
        .port();
    let server_address: SocketAddr = ([127, 0, 0, 1], server_port).into();
    let server_socket = Arc::<tokio::net::UdpSocket>::from(server_socket);

    let server_secret_key = SecretKey::gen();
    let server_private_key: Arc<X25519SecretKey> = Arc::new(
        server_secret_key
            .to_string()
            .parse()
            .expect("Failed to convert server private key"),
    );
    let server_public_key: Arc<X25519PublicKey> =
        Arc::new(X25519PublicKey::from(&server_secret_key.public()[..]));

    let client_secret_key = SecretKey::gen();
    let client_public_key = client_secret_key.public();
    let client_public_key: Arc<X25519PublicKey> =
        Arc::new(X25519PublicKey::from(&client_public_key[..]));

    let server_peer = Arc::<Tunn>::from(
        Tunn::new(server_private_key, client_public_key, None, None, 0, None)
            .expect("Failed to create server tunnel"),
    );

    let client = WGClient::new(client_secret_key, server_public_key, server_address).await;

    nameserver
        .start(
            server_peer.clone(),
            server_socket.clone(),
            client.client_address(),
        )
        .await;

    client.do_handshake().await;
    client.send_dns_request(query, test_type).await;
}

#[tokio::test]
async fn dns_request_local() {
    let mut records = Records::new();
    records.insert(
        String::from("test.nord."),
        (Some(Ipv4Addr::new(100, 100, 100, 100)), None),
    );
    let zone = String::from("nord");
    timeout(
        Duration::from_secs(60),
        dns_test("test.nord", DnsTestType::Correct, Some((zone, records))),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_forward() {
    timeout(
        Duration::from_secs(60),
        dns_test("google.com", DnsTestType::Correct, None),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_forward_to_slow_server() {
    let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))])
        .await
        .unwrap();

    // Start a query that will run for several seconds
    tokio::spawn(dns_test_with_server(
        "google.com",
        DnsTestType::Correct,
        None,
        nameserver.clone(),
    ));

    // Let it reach the state where we are waiting for external
    // server reply.
    sleep(Duration::from_millis(500)).await;

    // Verify that we still have write access to nameserver
    assert!(timeout(Duration::from_millis(100), nameserver.write())
        .await
        .is_ok());
}

#[tokio::test]
async fn dns_request_bad_ip_checksum() {
    timeout(
        Duration::from_secs(60),
        dns_test("google.com", DnsTestType::BadIpChecksum, None),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_checksum() {
    timeout(
        Duration::from_secs(60),
        dns_test("google.com", DnsTestType::BadUdpChecksum, None),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_port() {
    timeout(
        Duration::from_secs(60),
        dns_test("google.com", DnsTestType::BadUdpPort, None),
    )
    .await
    .expect("Test timeout");
}
