use boringtun::noise::{Tunn, TunnResult};
use dns_parser::{self, Builder, QueryClass, QueryType};
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    udp::{ipv4_checksum, ipv6_checksum, MutableUdpPacket, UdpPacket},
    Packet,
};
use rand::prelude::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use telio_dns::{LocalNameServer, NameServer, Records};
use telio_model::features::TtlValue;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use tokio::{
    self,
    time::{timeout, Duration},
};
use x25519_dalek::{PublicKey, StaticSecret};

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const MAX_PACKET: usize = 2048;

struct WGClient {
    client_socket: tokio::net::UdpSocket,
    client_address: SocketAddr,
    server_address: SocketAddr,
    tunnel: Arc<Mutex<Tunn>>,
}

impl WGClient {
    async fn new(
        client_secret_key: StaticSecret,
        server_public_key: PublicKey,
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
        let client_private_key = client_secret_key;
        WGClient {
            client_socket,
            client_address,
            server_address,
            tunnel: Arc::new(Mutex::new(
                Tunn::new(
                    client_private_key,
                    server_public_key.clone(),
                    None,
                    None,
                    0,
                    None,
                )
                .expect("Failed to create client tunnel"),
            )),
        }
    }

    async fn do_handshake(&self) {
        let mut sending_buffer = vec![0u8; MAX_PACKET];
        let mut receiving_buffer = vec![0u8; MAX_PACKET];

        match self
            .tunnel
            .lock()
            .await
            .encapsulate(&[], &mut sending_buffer)
        {
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
        match self.tunnel.lock().await.decapsulate(
            None,
            &receiving_buffer[..bytes_read],
            &mut sending_buffer,
        ) {
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

        match self
            .tunnel
            .lock()
            .await
            .encapsulate(&request[..], &mut sending_buffer)
        {
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
            if !test_type.is_correct() {
                // A timeout is expected during "Bad" scenarios.
                // The server should ignore bad requests.
                return;
            } else {
                panic!("Didn't receive a response from the server");
            }
        } else {
            if !test_type.is_correct() {
                panic!("Received a response when shouldn't");
            }
        }

        let bytes_read = result.unwrap().expect("Failed to recv from server");
        match self.tunnel.lock().await.decapsulate(
            None,
            &receiving_buffer[..bytes_read],
            &mut sending_buffer,
        ) {
            TunnResult::WriteToTunnelV4(response, _) => {
                if test_type.is_ipv6() {
                    panic!("Decapsulate into IPv4 for IPv6");
                }

                let ip_response = Ipv4Packet::new(response).expect("Failed to parse ip response");
                let udp_response =
                    UdpPacket::new(ip_response.payload()).expect("Failed to parse udp response");
                dns_parser::Packet::parse(udp_response.payload())
                    .expect("Failed to parse dns response");
            }
            TunnResult::WriteToTunnelV6(response, _) => {
                if test_type.is_ipv4() {
                    panic!("Decapsulate into IPv6 for IPv4");
                }

                let ip_response = Ipv6Packet::new(response).expect("Failed to parse ip response");
                let udp_response =
                    UdpPacket::new(ip_response.payload()).expect("Failed to parse udp response");
                dns_parser::Packet::parse(udp_response.payload())
                    .expect("Failed to parse dns response");
            }
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult while receiving the dns response"),
        }
    }

    fn build_dns_request(query: &str, test_type: DnsTestType) -> Vec<u8> {
        let mut builder = Builder::new_query(1, true);
        builder.add_question(query, false, QueryType::A, QueryClass::IN);
        let dns_query = builder.build().expect("Failed to build the dns query");

        if test_type.is_ipv4() {
            WGClient::build_ipv4_dns_request(&dns_query, test_type)
        } else {
            WGClient::build_ipv6_dns_request(&dns_query, test_type)
        }
    }

    fn build_ipv4_dns_request(dns_query: &[u8], test_type: DnsTestType) -> Vec<u8> {
        let length = IPV4_HEADER + UDP_HEADER + dns_query.len();
        let mut buffer = vec![0u8; MAX_PACKET];

        let local_address = Ipv4Addr::new(127, 0, 0, 1);

        {
            let mut ip_packet =
                MutableIpv4Packet::new(&mut buffer).expect("Failed to create MutableIpv4Packet");
            ip_packet.set_version(4);
            ip_packet.set_header_length((IPV4_HEADER / 4) as u8);
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
            if !matches!(test_type, DnsTestType::BadIpChecksumIpv4) {
                ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
            }
        }

        {
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[IPV4_HEADER..length])
                .expect("Failed to create MutableUdpPacket");
            udp_packet.set_source(100);
            udp_packet.set_destination(54);
            if !matches!(test_type, DnsTestType::BadUdpPortIpv4) {
                udp_packet.set_destination(53);
            }
            udp_packet.set_length((UDP_HEADER + dns_query.len()) as u16);
            udp_packet.set_payload(&dns_query);
            udp_packet.set_checksum(0);
            if !matches!(test_type, DnsTestType::BadUdpChecksumIpv4) {
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

    fn build_ipv6_dns_request(dns_query: &[u8], test_type: DnsTestType) -> Vec<u8> {
        let length = UDP_HEADER + dns_query.len();
        let total_length = IPV6_HEADER + length;
        let mut buffer = vec![0u8; MAX_PACKET];

        let local_address = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

        {
            let mut ip_response =
                MutableIpv6Packet::new(&mut buffer).expect("Failed to create MutableIpv6Packet");
            ip_response.set_version(6);
            ip_response.set_traffic_class(0);
            ip_response.set_flow_label(0);
            ip_response.set_payload_length(length as u16);
            ip_response.set_next_header(IpNextHeaderProtocols::Udp);
            ip_response.set_hop_limit(255);
            ip_response.set_source(local_address);
            ip_response.set_destination(local_address);
        }

        {
            let mut udp_response = MutableUdpPacket::new(&mut buffer[IPV6_HEADER..total_length])
                .expect("Failed to create MutableUdpPacket");
            udp_response.set_source(100);
            if matches!(test_type, DnsTestType::BadUdpPortIpv6) {
                udp_response.set_destination(54);
            } else {
                udp_response.set_destination(53);
            }
            udp_response.set_length(length as u16);
            udp_response.set_payload(dns_query);
            if matches!(test_type, DnsTestType::BadUdpChecksumIpv6) {
                udp_response.set_checksum(0);
            } else {
                udp_response.set_checksum(ipv6_checksum(
                    &udp_response.to_immutable(),
                    &local_address,
                    &local_address,
                ));
            }
        }

        buffer.truncate(total_length);
        buffer
    }

    fn client_address(&self) -> SocketAddr {
        self.client_address
    }
}

#[derive(Copy, Clone)]
enum DnsTestType {
    CorrectIpv4,
    BadIpChecksumIpv4,
    BadUdpChecksumIpv4,
    BadUdpPortIpv4,
    CorrectIpv6,
    BadUdpChecksumIpv6,
    BadUdpPortIpv6,
    NonRespondingForwardServer,
}

impl DnsTestType {
    fn is_ipv4(&self) -> bool {
        matches!(
            self,
            DnsTestType::CorrectIpv4
                | DnsTestType::BadIpChecksumIpv4
                | DnsTestType::BadUdpChecksumIpv4
                | DnsTestType::BadUdpPortIpv4
        )
    }

    fn is_ipv6(&self) -> bool {
        matches!(
            self,
            DnsTestType::CorrectIpv6
                | DnsTestType::BadUdpChecksumIpv6
                | DnsTestType::BadUdpPortIpv6
        )
    }

    fn is_correct(&self) -> bool {
        matches!(self, DnsTestType::CorrectIpv4 | DnsTestType::CorrectIpv6)
    }
}

async fn dns_test(
    query: &str,
    test_type: DnsTestType,
    local_records: Option<(String, Records)>,
    ttl_value: TtlValue,
) {
    let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
        .await
        .expect("Failed to create a LocalNameServer");

    dns_test_with_server(query, test_type, local_records, nameserver, ttl_value).await;
}

async fn dns_test_with_server(
    query: &str,
    test_type: DnsTestType,
    local_records: Option<(String, Records)>,
    nameserver: Arc<RwLock<LocalNameServer>>,
    ttl_value: TtlValue,
) {
    if let Some((zone, records)) = local_records {
        nameserver
            .upsert(&zone, &records, ttl_value)
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

    let server_private_key = StaticSecret::new(&mut rand::rngs::StdRng::from_entropy());
    let server_public_key = PublicKey::from(&server_private_key);

    let client_secret_key = StaticSecret::new(&mut rand::rngs::StdRng::from_entropy());
    let client_public_key = PublicKey::from(&client_secret_key);

    let server_peer = Arc::new(Mutex::new(
        Tunn::new(server_private_key, client_public_key, None, None, 0, None)
            .expect("Failed to create server tunnel"),
    ));

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
async fn dns_request_local_ipv4() {
    let mut records = Records::new();
    records.insert(
        String::from("test.nord."),
        vec![IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))],
    );
    let zone = String::from("nord");
    timeout(
        Duration::from_secs(60),
        dns_test(
            "test.nord",
            DnsTestType::CorrectIpv4,
            Some((zone, records)),
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_local_ipv6() {
    let mut records = Records::new();
    records.insert(
        String::from("test.nord."),
        vec![
            IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
            IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)),
        ],
    );
    let zone = String::from("nord");
    timeout(
        Duration::from_secs(60),
        dns_test(
            "test.nord",
            DnsTestType::CorrectIpv6,
            Some((zone, records)),
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_forward() {
    timeout(
        Duration::from_secs(60),
        dns_test("google.com", DnsTestType::CorrectIpv4, None, TtlValue(60)),
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
        DnsTestType::NonRespondingForwardServer,
        None,
        nameserver.clone(),
        TtlValue(60),
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
async fn dns_request_to_non_responding_forward_server() {
    let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))])
        .await
        .unwrap();

    dns_test_with_server(
        "google.com",
        DnsTestType::NonRespondingForwardServer,
        None,
        nameserver.clone(),
        TtlValue(60),
    )
    .await;
}

#[tokio::test]
async fn dns_request_bad_ip_checksum_ipv4() {
    timeout(
        Duration::from_secs(60),
        dns_test(
            "google.com",
            DnsTestType::BadIpChecksumIpv4,
            None,
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_checksum_ipv4() {
    timeout(
        Duration::from_secs(60),
        dns_test(
            "google.com",
            DnsTestType::BadUdpChecksumIpv4,
            None,
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_checksum_ipv6() {
    timeout(
        Duration::from_secs(60),
        dns_test(
            "google.com",
            DnsTestType::BadUdpChecksumIpv6,
            None,
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_port_ipv4() {
    timeout(
        Duration::from_secs(60),
        dns_test(
            "google.com",
            DnsTestType::BadUdpPortIpv4,
            None,
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}

#[tokio::test]
async fn dns_request_bad_udp_port_ipv6() {
    timeout(
        Duration::from_secs(60),
        dns_test(
            "google.com",
            DnsTestType::BadUdpPortIpv6,
            None,
            TtlValue(60),
        ),
    )
    .await
    .expect("Test timeout");
}
