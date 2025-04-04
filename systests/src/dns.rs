use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use pnet_packet::dns::{DnsPacket, DnsTypes};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::utils::process_wrapper::ProcessWrapper;

pub const DNS_IP: Ipv4Addr = Ipv4Addr::new(127, 64, 0, 2);
pub const DNS_PORT: u16 = 53;

#[derive(thiserror::Error, Clone, Debug)]
pub enum DnsError {
    #[error("DNS request for {0} timed out")]
    Timeout(String),
    #[error("DNS request returned the wrong IP: {0}")]
    WrongIp(IpAddr),
}

#[derive(Serialize, Deserialize, Default)]
pub struct DnsConfig {
    hosts: HashMap<String, IpAddr>,
}

impl DnsConfig {
    pub fn add_ip(mut self, host: &str, ip: IpAddr) -> Self {
        self.hosts.insert(host.to_owned(), ip);
        self
    }

    pub fn get_ip_for_host(&self, host: &str) -> Option<IpAddr> {
        self.hosts.get(host).copied()
    }
}

pub struct Dns {
    proc: ProcessWrapper,
}

impl Dns {
    pub async fn start(config: DnsConfig) -> Self {
        let mut proc = ProcessWrapper::new("./target/debug/dns", "dns".to_owned()).unwrap();

        let cfg = serde_json::to_string(&config).unwrap();
        proc.write_stdin(&cfg).await.unwrap();

        while let Some(line) = proc.read_stdout().await {
            match line.as_str() {
                "ready" => {
                    println!("DNS server is ready to serve requests");
                    break;
                }
                "error" => {
                    eprintln!("Something went wrong");
                    std::process::exit(1);
                }
                _ => {
                    println!("Unexpected output: {line}");
                }
            }
        }

        Self { proc }
    }

    pub async fn stop(self) {
        self.proc.kill().await;
    }

    pub async fn send_query(from: IpAddr, hostname: String) -> Result<IpAddr, DnsError> {
        let fut = async {
            let packet = Self::create_dns_request(&hostname);
            let socket = UdpSocket::bind(SocketAddr::new(from, 0)).await.unwrap();
            socket
                .send_to(
                    &packet,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), DNS_PORT),
                )
                .await
                .unwrap();

            let mut response = vec![0u8; 512];
            loop {
                match socket.recv_from(&mut response).await {
                    Ok((len, from)) => {
                        println!("Received from: {from}");
                        let dns = DnsPacket::new(&response[..len]);
                        if let Some(dns) = dns {
                            println!("Received dns response");
                            let resp = dns.get_responses().iter().find_map(|r| match r.rtype {
                                DnsTypes::A => {
                                    let octets: [u8; 4] = r.data[..4].try_into().unwrap();
                                    Some(IpAddr::V4(Ipv4Addr::from(octets)))
                                }
                                DnsTypes::AAAA => {
                                    let octets: [u8; 16] = r.data[..16].try_into().unwrap();
                                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                                }
                                _ => None,
                            });
                            if let Some(ip) = resp {
                                return Ok(ip);
                            }
                        } else {
                            println!("Received different packet");
                        }
                    }
                    Err(e) => {
                        eprintln!("Socket read error: {e:?}");
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .map_err(|_| DnsError::Timeout(hostname))?
    }

    fn create_dns_request(hostname: &str) -> Vec<u8> {
        let mut packet = vec![0u8; 512];
        // Transaction ID (random 16-bit number)
        packet[0] = OsRng.gen();
        packet[1] = OsRng.gen();

        // Flags: Standard Query (0x0100)
        packet[2] = 0x01;
        packet[3] = 0x00;

        // Questions: 1
        packet[4] = 0x00;
        packet[5] = 0x01;

        // Answer, Authority, Additional RRs: 0
        packet[6] = 0x00;
        packet[7] = 0x00;
        packet[8] = 0x00;
        packet[9] = 0x00;
        packet[10] = 0x00;
        packet[11] = 0x00;

        // Query: "google.com"
        let mut pos = 12;
        for label in hostname.split('.') {
            packet[pos] = label.len() as u8;
            pos += 1;
            packet[pos..pos + label.len()].copy_from_slice(label.as_bytes());
            pos += label.len();
        }

        // Null terminator for domain name
        packet[pos] = 0;
        pos += 1;

        // Query Type: A (0x0001)
        packet[pos] = 0x00;
        packet[pos + 1] = 0x01;
        pos += 2;

        // Query Class: IN (0x0001)
        packet[pos] = 0x00;
        packet[pos + 1] = 0x01;
        pos += 2;

        packet.truncate(pos); // Keep only the used bytes
        packet
    }
}
