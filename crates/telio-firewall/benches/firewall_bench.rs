use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::rc::Rc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pnet_packet::tcp::TcpFlags;
use telio_crypto::SecretKey;
use telio_firewall::firewall::tests::{make_tcp, make_tcp6, make_udp, make_udp6};
use telio_firewall::firewall::{Firewall, Permissions, StatefullFirewall};
use telio_model::features::FeatureFirewall;

const PEER_COUNTS: [usize; 8] = [0, 1, 2, 4, 8, 16, 32, 64]; // max 60 peers: https://meshnet.nordvpn.com/getting-started/meshnet-explained#meshnet-scalability
const PACKET_COUNT: u64 = 100_000;

#[derive(Clone)]
struct Packet {
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
    packet_maker: Rc<dyn Fn(&str, &str) -> Vec<u8>>,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("src", &self.src)
            .field("dst", &self.dst)
            .field("payload", &self.payload)
            .finish()
    }
}
impl Deref for Packet {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl Packet {
    /// Create new packet and precompute new serialized packet in `payload` field.
    fn new(src: &str, dst: &str, packet_maker: impl Fn(&str, &str) -> Vec<u8> + 'static) -> Self {
        let payload = packet_maker(src, dst);
        Self {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            payload,
            packet_maker: Rc::new(packet_maker),
        }
    }

    /// Create new packet based on the packet making function used when creating `self`.
    fn make(&self, src: impl ToString, dst: impl ToString) -> Vec<u8> {
        (self.packet_maker)(&src.to_string(), &dst.to_string())
    }
}

#[derive(Debug, Clone)]
struct Parameter {
    peers: usize,
    packet: Packet,
}

impl Display for Parameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ip = if self.packet.src.is_ipv4() { 4 } else { 6 };
        write!(f, "peers: {}, ip: v{ip}", self.peers)
    }
}

pub fn firewall_tcp_inbound_benchmarks(c: &mut Criterion) {
    let packets = [
        Packet::new("8.8.8.8:8888", "127.0.0.1:1111", |s, d| {
            make_tcp(s, d, TcpFlags::SYN)
        }),
        Packet::new("[2001:4860:4860::8888]:8888", "[::1]:1111", |s, d| {
            make_tcp6(s, d, TcpFlags::SYN)
        }),
    ];
    {
        let mut group = c.benchmark_group("process inbound tcp packet - rejected");
        for packet in &packets {
            for peers in PEER_COUNTS {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(!firewall
                                    .process_inbound_packet(&peers[which_peer], &param.packet));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound tcp packet - accepted because of peer");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        let mut peers = vec![];
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall
                                    .process_inbound_packet(&peers[which_peer], &param.packet));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound tcp packet - accepted because of port");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        let mut peers_and_packets = vec![];
                        let port_base = 1111;
                        for i in 0..param.peers {
                            let port = (port_base + i) as u16;
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, port);
                            let packet = packet.make(
                                param.packet.src,
                                SocketAddr::new(param.packet.dst.ip(), port),
                            );
                            peers_and_packets.push((public_key.0, packet));
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_inbound_packet(
                                    &peers_and_packets[which_peer].0,
                                    &peers_and_packets[which_peer].1,
                                ));
                                which_peer = (which_peer + 1) % peers_and_packets.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound tcp from vpn peer packet - accepted");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);

                        let public_key = SecretKey::gen().public();
                        firewall.add_vpn_peer(public_key);

                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(
                                    firewall.process_inbound_packet(&public_key.0, &param.packet)
                                );
                            }
                        });
                    },
                );
            }
        }
    }
}

pub fn firewall_tcp_outbound_benchmarks(c: &mut Criterion) {
    {
        let packets = [
            Packet::new("8.8.8.8:8888", "127.0.0.1:1111", |s, d| {
                make_tcp(s, d, TcpFlags::SYN)
            }),
            Packet::new("[2001:4860:4860::8888]:8888", "[::1]:1111", |s, d| {
                make_tcp6(s, d, TcpFlags::SYN)
            }),
        ];
        let mut group = c.benchmark_group("process outbound tcp packet - SYN");
        for packet in &packets {
            for peers in PEER_COUNTS {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let peer_pk1 = SecretKey::gen().public();
                        let peer_pk2 = SecretKey::gen().public();
                        let peers = [peer_pk1.0, peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_outbound_packet(
                                    &peers[which_peer],
                                    &param.packet,
                                    &mut &std::io::sink()
                                ));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    let packets = [
        Packet::new("8.8.8.8:8888", "127.0.0.1:1111", |s, d| make_tcp(s, d, 0)),
        Packet::new("[2001:4860:4860::8888]:8888", "[::1]:1111", |s, d| {
            make_tcp6(s, d, 0)
        }),
    ];
    {
        let mut group = c.benchmark_group("process outbound tcp packet - other");
        for packet in &packets {
            for peers in PEER_COUNTS {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_outbound_packet(
                                    &peers[which_peer],
                                    &param.packet,
                                    &mut &std::io::sink()
                                ));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process outbound tcp packet - accepted because of peer");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        let mut peers = vec![];
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_outbound_packet(
                                    &peers[which_peer],
                                    &param.packet,
                                    &mut &std::io::sink()
                                ));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }
}

pub fn firewall_udp_inbound_benchmarks(c: &mut Criterion) {
    let packets = [
        Packet::new("8.8.8.8:8888", "127.0.0.1:42", make_udp),
        Packet::new("[2001:4860:4860::8888]:8888", "[::1]:42", make_udp6),
    ];
    {
        let mut group = c.benchmark_group("process inbound udp packet - rejected");
        for packet in &packets {
            for peers in PEER_COUNTS {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(!firewall
                                    .process_inbound_packet(&peers[which_peer], &param.packet));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound udp packet - accepted because of peer");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        let mut peers = vec![];
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall
                                    .process_inbound_packet(&peers[which_peer], &param.packet));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound udp packet - accepted because of port");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);
                        let mut peers_and_packets = vec![];
                        let port_base = 42;
                        for i in 0..param.peers {
                            let port = (port_base + i) as u16;
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, port as u16);
                            let packet = param.packet.make(
                                param.packet.src,
                                SocketAddr::new(param.packet.dst.ip(), port),
                            );
                            peers_and_packets.push((public_key.0, packet));
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_inbound_packet(
                                    &peers_and_packets[which_peer].0,
                                    &peers_and_packets[which_peer].1,
                                ));
                                which_peer = (which_peer + 1) % peers_and_packets.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound udp from vpn peer packet - accepted");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        firewall.set_ip_addresses(vec![
                            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        ]);

                        let public_key = SecretKey::gen().public();
                        firewall.add_vpn_peer(public_key);

                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(
                                    firewall.process_inbound_packet(&public_key.0, &param.packet)
                                );
                            }
                        });
                    },
                );
            }
        }
    }
}

pub fn firewall_udp_outbound_benchmarks(c: &mut Criterion) {
    let packets = [
        Packet::new("8.8.8.8:8888", "127.0.0.1:42", make_udp),
        Packet::new("[2001:4860:4860::8888]:8888", "[::1]:42", make_udp6),
    ];
    {
        let mut group = c.benchmark_group("process outbound udp packet - accepted because of peer");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        let mut peers = vec![];
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(
                                public_key,
                                Permissions::IncomingConnections,
                            );
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_outbound_packet(
                                    &peers[which_peer],
                                    &param.packet,
                                    &mut &std::io::sink()
                                ));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process outbound udp packet - accepted");
        for packet in &packets {
            for peers in PEER_COUNTS[1..].iter().copied() {
                group.throughput(criterion::Throughput::Elements(PACKET_COUNT));
                let parameter = Parameter {
                    peers,
                    packet: packet.clone(),
                };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter.clone()),
                    &parameter,
                    |b, param| {
                        let firewall = StatefullFirewall::new(true, &FeatureFirewall::default());
                        let mut peers = vec![];
                        for _ in 0..param.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, 42);
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..PACKET_COUNT {
                                assert!(firewall.process_outbound_packet(
                                    &peers[which_peer],
                                    &param.packet,
                                    &mut &std::io::sink()
                                ));
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }
}

criterion_group!(
    benches,
    firewall_tcp_inbound_benchmarks,
    firewall_tcp_outbound_benchmarks,
    firewall_udp_inbound_benchmarks,
    firewall_udp_outbound_benchmarks
);
criterion_main!(benches);
