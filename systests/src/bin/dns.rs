use pnet_packet::dns::{DnsPacket, DnsTypes::A};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use systests::dns::{DnsConfig, DNS_IP, DNS_PORT};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UdpSocket,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let cfg_str = reader
        .lines()
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to read from stdout"))?;
    let config = serde_json::from_str::<DnsConfig>(&cfg_str)?;
    let socket = UdpSocket::bind(SocketAddrV4::new(DNS_IP, DNS_PORT)).await?;
    Dns {
        config,
        socket,
        buffer: [0u8; 512],
    }
    .run()
    .await;

    Ok(())
}

struct Dns {
    config: DnsConfig,
    socket: UdpSocket,
    buffer: [u8; 512],
}

impl Dns {
    async fn run(mut self) {
        println!("ready");
        loop {
            if let Ok((len, addr)) = self.socket.recv_from(&mut self.buffer).await {
                self.handle_request(len, addr).await;
            }
        }
    }

    async fn handle_request(&mut self, len: usize, addr: SocketAddr) {
        if let Some(response) = self.create_dns_response(len) {
            let _ = self.socket.send_to(&response, addr).await;
        }
    }

    fn create_dns_response(&self, len: usize) -> Option<Vec<u8>> {
        let request = &self.buffer[..len];
        let mut response = Vec::new();

        let request_packet = match DnsPacket::new(request) {
            Some(pkt) => pkt,
            None => return None,
        };
        let host = request_packet
            .get_queries()
            .iter()
            .find(|q| q.qtype == A)
            .cloned();
        println!("Recieved request for '{host:?}'");
        let ip = host.and_then(|q| self.config.get_ip_for_host(q.get_qname_parsed().as_str()));

        // Copy request bytes
        response.extend_from_slice(request);
        // Set response flag
        response[2] |= 0b10000000;

        // If we have an IP for the hostname return it, otherwise return error
        if let Some(IpAddr::V4(ip)) = ip {
            // Set number of responses to 1
            response[7] = 1;
            // Add response to list of responses
            let answer = vec![
                0xc0, 0x0c, // "query tag", i.e. use the same name as the first query
                0, 1, // IN query
                0, 1, // A record
                0, 0, 0, 60, // TTL 60 seconds
                0, 4, // Data length 4 bytes, since IPv4 address has 4 octets
            ];
            response.extend_from_slice(&answer);
            response.extend_from_slice(&ip.octets());
        } else {
            // Set return code to NXDOMAIN, meaning that we have no record for the hostname
            response[3] |= 3;
        }

        Some(response)
    }
}
