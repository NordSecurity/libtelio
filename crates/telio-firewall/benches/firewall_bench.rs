use std::fmt::Display;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pnet_packet::tcp::TcpFlags;
use telio_crypto::SecretKey;
use telio_firewall::firewall::tests::{make_tcp, make_udp};
use telio_firewall::firewall::{Firewall, StatefullFirewall};

const PEER_COUNTS: [usize; 8] = [0, 1, 2, 4, 8, 16, 32, 64]; // max 60 peers: https://meshnet.nordvpn.com/getting-started/meshnet-explained#meshnet-scalability
const PACKET_COUNTS: [u64; 2] = [1_000, 100_000];

#[derive(Debug, Clone, Copy)]
struct Parameter {
    peers: usize,
    packets: u64,
}

impl Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub fn firewall_tcp_inbound_benchmarks(c: &mut Criterion) {
    let packet = make_tcp("8.8.8.8:8888", "127.0.0.1:1111", TcpFlags::SYN);
    {
        let mut group = c.benchmark_group("process inbound tcp packet - rejected");
        for peers in PEER_COUNTS {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    !firewall.process_inbound_packet(&peers[which_peer], &packet)
                                );
                                which_peer = (which_peer + 1) % peers.len();
                            }
                            assert_eq!((0, 0), firewall.get_state());
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound tcp packet - accepted because of peer");
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers = vec![];
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_inbound_packet(&peers[which_peer], &packet)
                                );
                                which_peer = (which_peer + 1) % peers.len();
                            }
                            assert_eq!((0, 0), firewall.get_state());
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound tcp packet - accepted because of port");
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers_and_packets = vec![];
                        let port_base = 1111;
                        for i in 0..p.peers {
                            let port = port_base + i;
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, port as u16);
                            let packet = make_tcp(
                                "8.8.8.8:8888",
                                &format!("127.0.0.1:{port}"),
                                TcpFlags::SYN,
                            );
                            peers_and_packets.push((public_key.0, packet));
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(firewall.process_inbound_packet(
                                    &peers_and_packets[which_peer].0,
                                    &peers_and_packets[which_peer].1,
                                ));
                                which_peer = (which_peer + 1) % peers_and_packets.len();
                            }
                            assert_eq!((peers_and_packets.len(), 0), firewall.get_state());
                        });
                    },
                );
            }
        }
    }
}

pub fn firewall_tcp_outbound_benchmarks(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("process outbound tcp packet - SYN");
        for peers in PEER_COUNTS {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let peer_pk1 = SecretKey::gen().public();
                        let peer_pk2 = SecretKey::gen().public();
                        let peers = [peer_pk1.0, peer_pk2.0];
                        let packet = make_tcp("8.8.8.8:8888", "127.0.0.1:1111", TcpFlags::SYN);
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_outbound_packet(&peers[which_peer], &packet)
                                );
                                which_peer = (which_peer + 1) % peers.len();
                            }
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process outbound tcp packet - other");
        for peers in PEER_COUNTS {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let packet = make_tcp("8.8.8.8:8888", "127.0.0.1:1111", 0);
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_outbound_packet(&peers[which_peer], &packet)
                                );
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
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers = vec![];
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            peers.push(public_key.0);
                        }
                        let packet = make_tcp("8.8.8.8:8888", "127.0.0.1:1111", 0);
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_outbound_packet(&peers[which_peer], &packet)
                                );
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
    let packet = make_udp("8.8.8.8:8888", "127.0.0.1:42");
    {
        let mut group = c.benchmark_group("process inbound udp packet - rejected");
        for peers in PEER_COUNTS {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            firewall.add_to_port_whitelist(public_key, 42);
                        }
                        let other_peer_pk1 = SecretKey::gen().public();
                        let other_peer_pk2 = SecretKey::gen().public();
                        let peers = [other_peer_pk1.0, other_peer_pk2.0];
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    !firewall.process_inbound_packet(&peers[which_peer], &packet)
                                );
                                which_peer = (which_peer + 1) % peers.len();
                            }
                            assert_eq!((0, 0), firewall.get_state());
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound udp packet - accepted because of peer");
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers = vec![];
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_inbound_packet(&peers[which_peer], &packet)
                                );
                                which_peer = (which_peer + 1) % peers.len();
                            }
                            assert_eq!((0, 0), firewall.get_state());
                        });
                    },
                );
            }
        }
    }

    {
        let mut group = c.benchmark_group("process inbound udp packet - accepted because of port");
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers_and_packets = vec![];
                        let port_base = 42;
                        for i in 0..p.peers {
                            let port = port_base + i;
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, port as u16);
                            let packet = make_udp("8.8.8.8:8888", &format!("127.0.0.1:{port}"));
                            peers_and_packets.push((public_key.0, packet));
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(firewall.process_inbound_packet(
                                    &peers_and_packets[which_peer].0,
                                    &peers_and_packets[which_peer].1,
                                ));
                                which_peer = (which_peer + 1) % peers_and_packets.len();
                            }
                            assert_eq!((0, peers_and_packets.len()), firewall.get_state());
                        });
                    },
                );
            }
        }
    }
}

pub fn firewall_udp_outbound_benchmarks(c: &mut Criterion) {
    let packet = make_udp("8.8.8.8:8888", "127.0.0.1:42");
    {
        let mut group = c.benchmark_group("process outbound udp packet - accepted because of peer");
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers = vec![];
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_peer_whitelist(public_key);
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_outbound_packet(&peers[which_peer], &packet)
                                );
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
        for peers in PEER_COUNTS[1..].iter().copied() {
            for packets in PACKET_COUNTS {
                group.throughput(criterion::Throughput::Elements(packets as u64));
                let parameter = Parameter { peers, packets };
                group.bench_with_input(
                    BenchmarkId::from_parameter(parameter),
                    &parameter,
                    |b, &p| {
                        let firewall = StatefullFirewall::new();
                        let mut peers = vec![];
                        for _ in 0..p.peers {
                            let public_key = SecretKey::gen().public();
                            firewall.add_to_port_whitelist(public_key, 42);
                            peers.push(public_key.0);
                        }
                        let mut which_peer = 0usize;
                        b.iter(|| {
                            for _ in 0..p.packets {
                                assert!(
                                    firewall.process_outbound_packet(&peers[which_peer], &packet)
                                );
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
