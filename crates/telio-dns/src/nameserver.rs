use crate::{
    resolver::Resolver,
    zone::{AuthoritativeZone, ClonableZones, ForwardZone, Records},
};
use async_trait::async_trait;
use hickory_server::{
    authority::MessageRequest,
    proto::{rr::LowerName, serialize::binary::BinDecodable},
    server::{Protocol, Request},
};
use neptun::noise::{Tunn, TunnResult};
use pnet_packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    udp::{ipv4_checksum, ipv6_checksum, MutableUdpPacket, UdpPacket},
    Packet,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use telio_model::features::TtlValue;
use tokio::sync::{RwLock, RwLockMappedWriteGuard, RwLockWriteGuard, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio::{net::UdpSocket, sync::Mutex};

use telio_utils::{format_hex, telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};

const IPV4_HEADER: usize = 20; // bytes
const IPV6_HEADER: usize = 40; // bytes
const MAX_PACKET: usize = 2048;
const UDP_HEADER: usize = 8;
const TCP_MIN_HEADER: usize = 20;
const MAX_CONCURRENT_QUERIES: usize = 256;
const IDLE_TIME: Duration = Duration::from_secs(1);

/// NameServer is a server that stores the DNS records.
#[async_trait]
pub trait NameServer {
    /// Start the server.
    ///
    /// Server will listen on `socket`, expect connections from `peer` and will
    /// reply to `dst_address`.
    async fn start(&self, peer: Arc<Mutex<Tunn>>, socket: Arc<UdpSocket>);
    /// Stop the server.
    async fn stop(&self);
    /// Configure list of forward DNS servers for zone '.'.
    async fn forward(&self, to: &[IpAddr]) -> Result<(), String>;
    /// Insert or update zone records used by the server.
    async fn upsert(
        &self,
        zone: &str,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<(), String>;
}

/// Helper to update wg timers
async fn update_wg_timers(
    peer: &Arc<Mutex<Tunn>>,
    socket: &Arc<UdpSocket>,
    sender_addr: SocketAddr,
) {
    let mut sending_buffer = vec![0u8; MAX_PACKET];
    loop {
        // Drain update_timers until Done or Error is returned
        let res = peer.lock().await.update_timers(&mut sending_buffer);
        match res {
            TunnResult::WriteToNetwork(packet) => {
                if let Err(e) = socket.send_to(packet, sender_addr).await {
                    telio_log_warn!("[DNS] Failed to send timer update packet: {:?}", e)
                };
            }
            TunnResult::Err(e) => {
                telio_log_warn!("[DNS] Failed to update Tunn timers: {:?}", e);
                break;
            }
            _ => break,
        };
    }
}

/// Local name server.
#[derive(Default)]
pub struct LocalNameServer {
    zones: Arc<ClonableZones>,
    task_handle: Option<JoinHandle<()>>,
}

impl LocalNameServer {
    /// Create a new `LocalNameServer` with forwarding dns servers from `forward_ips`
    /// configured for zone `.`.
    pub async fn new(forward_ips: &[IpAddr]) -> Result<Arc<RwLock<Self>>, String> {
        let ns = Arc::new(RwLock::new(LocalNameServer {
            zones: Arc::new(ClonableZones::new()),
            task_handle: None,
        }));
        ns.forward(forward_ips).await?;
        Ok(ns)
    }

    async fn dns_service(
        peer: Arc<Mutex<Tunn>>,
        nameserver: Arc<RwLock<LocalNameServer>>,
        socket: Arc<UdpSocket>,
    ) {
        let mut receiving_buffer = vec![0u8; MAX_PACKET];
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));

        // Remember where to send timer packets when idle.
        let mut last_sender: Option<SocketAddr> = None;
        let mut idle_timer = telio_utils::interval(IDLE_TIME);

        loop {
            tokio::select! {
                res = socket.recv_from(&mut receiving_buffer) => {
                    let (bytes_read, sender_addr) = match res {
                        Ok((bytes, sender_addr)) => (bytes, sender_addr),
                        Err(e) => {
                            telio_log_error!("[DNS] Failed to read bytes: {:?}", e);
                            continue;
                        }
                    };

                    if sender_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
                    {
                        telio_log_debug!(
                            "[DNS] Received packet from unexpected address: {:?}",
                            sender_addr
                        );
                        continue;
                    }

                    last_sender = Some(sender_addr);
                    idle_timer.reset();
                    update_wg_timers(&peer, &socket, sender_addr).await;

                    let peer = peer.clone();
                    let socket = socket.clone();
                    let nameserver = nameserver.clone();
                    let semaphore = semaphore.clone();
                    let in_bytes = Vec::from(receiving_buffer.get(..bytes_read).unwrap_or_default());

                    tokio::spawn(async move {
                        let mut sending_buffer = vec![0u8; MAX_PACKET];
                        let mut task_receiving_buffer = vec![0u8; MAX_PACKET];

                        let res = peer.lock().await.decapsulate(
                            None,
                            &in_bytes,
                            &mut sending_buffer,
                        );
                        match res {
                            // Handshake packets
                            TunnResult::WriteToNetwork(packet) => {
                                if let Err(e) = socket.send_to(packet, sender_addr).await {
                                    telio_log_warn!("[DNS] Failed to send handshake packet: {:?}", e);
                                    return;
                                };
                                let mut temporary_buffer = vec![0u8; MAX_PACKET];

                                while let TunnResult::WriteToNetwork(empty) =
                                peer.lock()
                                    .await
                                    .decapsulate(None, &[], &mut temporary_buffer)
                                {
                                    if let Err(e) = socket.send_to(empty, sender_addr).await {
                                        telio_log_warn!("[DNS] Failed to send handshake packet: {:?}", e);
                                        return;
                                    };
                                }
                            }
                            // DNS packets
                            TunnResult::WriteToTunnel(packet, _) => {
                                let _lease = match semaphore.acquire().await {
                                    Ok(lease) => lease,
                                    Err(_) => {
                                        telio_log_debug!("[DNS] Error semaphore.acquire()");
                                        return;
                                    }
                                };

                                let length = match LocalNameServer::process_packet(
                                    nameserver,
                                    packet,
                                    &mut task_receiving_buffer,
                                )
                                .await
                                {
                                    Ok(length) => length,
                                    Err(e) => {
                                        telio_log_debug!(
                                            "[DNS] {}. Offending request packet: [{:?}]",
                                            e,
                                            format_hex(packet)
                                        );
                                        return;
                                    }
                                };

                                let tunn_res = peer.lock().await.encapsulate(
                                    task_receiving_buffer.get(..length).unwrap_or(&[]),
                                    &mut sending_buffer,
                                );
                                match tunn_res {
                                    TunnResult::WriteToNetwork(dns) => {
                                        if let Err(e) = socket.send_to(dns, sender_addr).await {
                                            telio_log_warn!(
                                                "[DNS] Failed to send DNS query response: {:?}",
                                                e
                                            )
                                        };
                                    }
                                    TunnResult::Err(e) => {
                                        telio_log_warn!(
                                            "[DNS] Failed to encapsulate DNS query response: {:?}",
                                            e
                                        )
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    });
                },
                // LLT-5597: periodic tick to drive timers when there is no traffic
                _ = idle_timer.tick() => {
                    if let Some(last_sender) = last_sender {
                        telio_log_trace!("[DNS] Peer was idle, updating WG timers");
                        // update_wg_timers(&peer, &socket, last_sender).await;
                    }
                }
                else => {
                    telio_log_warn!("[DNS] all select branches disabled");
                    return;
                }
            }
        }
    }

    async fn resolve_dns_request(
        nameserver: Arc<RwLock<LocalNameServer>>,
        request_info: &mut RequestInfo,
    ) -> Result<Vec<u8>, String> {
        telio_log_debug!("Resolving dns");
        let resolver = Resolver::new();
        telio_log_debug!("Getting DNS zones");
        let zones = nameserver.zones().await;

        telio_log_debug!("Preparing DNS request");
        let dns_request = match &mut request_info.payload {
            PayloadRequestInfo::Udp {
                ref mut dns_request,
                ..
            } => dns_request
                .take()
                .ok_or_else(|| String::from("Inexistent DNS request"))?,
            _ => return Ok(Vec::new()),
        };
        let dns_request = Request::new(dns_request, request_info.dns_source(), Protocol::Udp);
        telio_log_debug!("DNS request: {:?}", &dns_request);

        zones
            .lookup(&dns_request, resolver.clone())
            .await
            .map_err(|e| format!("Lookup failed {e}"))?;

        let dns_response = resolver.0.lock().await;
        telio_log_debug!("Nameserver response: {:?}", &dns_response);
        Ok(dns_response.to_vec())
    }

    async fn process_packet(
        nameserver: Arc<RwLock<LocalNameServer>>,
        request_packet: &[u8],
        response_packet: &mut [u8],
    ) -> Result<usize, String> {
        let mut request_info = request_packet
            .first()
            .ok_or_else(|| String::from("Empty request packet"))
            .and_then(|first_byte| match first_byte >> 4 {
                4 => LocalNameServer::process_ip_packet::<Ipv4Packet>(request_packet),
                6 => LocalNameServer::process_ip_packet::<Ipv6Packet>(request_packet),
                _ => Err(String::from("Invalid IP version")),
            })?;

        let dns_response =
            LocalNameServer::resolve_dns_request(nameserver, &mut request_info).await?;

        request_info.build_response_packet(&dns_response, response_packet)
    }

    fn process_ip_packet<'a, P: IpPacket<'a>>(
        request_packet: &'a [u8],
    ) -> Result<RequestInfo, String> {
        let ip = P::try_from(request_packet)
            .ok_or_else(|| String::from("Failed to build IpPacket from request packet"))?;

        if !ip.check_valid() {
            return Err(String::from("Invalid IpPacket"));
        }

        let payload = match ip.next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                let udp_request = UdpPacket::new(ip.payload())
                    .ok_or_else(|| String::from("Failed to build UdpPacket from request packet"))?;
                LocalNameServer::process_udp_packet(&udp_request, |udp_packet| {
                    ip.udp_checksum(udp_packet)
                })?
            }
            IpNextHeaderProtocols::Tcp => {
                let tcp_request = TcpPacket::new(ip.payload())
                    .ok_or_else(|| String::from("Failed to build TcpPacket from request packet"))?;
                PayloadRequestInfo::Tcp {
                    source_port: tcp_request.get_source(),
                    destination_port: tcp_request.get_destination(),
                    next_sequence: tcp_request.get_sequence() + 1,
                }
            }
            _ => {
                return Err(String::from("Invalid protocol for DNS request"));
            }
        };

        Ok(RequestInfo {
            ip: ip.ip_request_info(),
            payload,
        })
    }

    fn process_udp_packet<F: Fn(&UdpPacket) -> u16>(
        udp_request: &UdpPacket,
        get_checksum: F,
    ) -> Result<PayloadRequestInfo, String> {
        // Validate UDP checksum
        if get_checksum(udp_request) != udp_request.get_checksum() {
            return Err(String::from("Invalid UDP checksum"));
        }

        // Validate DNS port
        if udp_request.get_destination() != 53 {
            return Err(String::from("Invalid DNS port"));
        }

        let dns_request = MessageRequest::from_bytes(udp_request.payload())
            .map_err(|_| String::from("Failed to build MessageRequest from request packet"))?;

        Ok(PayloadRequestInfo::Udp {
            source_port: udp_request.get_source(),
            destination_port: udp_request.get_destination(),
            dns_request: Some(dns_request),
        })
    }
}

enum IpRequestInfo {
    V4 {
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        dscp: u8,
        ecn: u8,
        ttl: u8,
        identification: u16,
    },
    V6 {
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
    },
}

impl IpRequestInfo {
    fn source_ip(&self) -> IpAddr {
        match self {
            IpRequestInfo::V4 { source_ip, .. } => IpAddr::V4(*source_ip),
            IpRequestInfo::V6 { source_ip, .. } => IpAddr::V6(*source_ip),
        }
    }

    fn compute_udp_checksum(&self, packet: &UdpPacket) -> u16 {
        match &self {
            IpRequestInfo::V4 {
                source_ip,
                destination_ip,
                ..
            } => ipv4_checksum(packet, destination_ip, source_ip),
            IpRequestInfo::V6 {
                source_ip,
                destination_ip,
                ..
            } => ipv6_checksum(packet, destination_ip, source_ip),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum PayloadRequestInfo {
    Udp {
        source_port: u16,
        destination_port: u16,
        dns_request: Option<MessageRequest>,
    },
    Tcp {
        source_port: u16,
        destination_port: u16,
        next_sequence: u32,
    },
}

struct RequestInfo {
    ip: IpRequestInfo,
    payload: PayloadRequestInfo,
}

impl RequestInfo {
    fn dns_source(&self) -> SocketAddr {
        let source_port = match self.payload {
            PayloadRequestInfo::Udp { source_port, .. }
            | PayloadRequestInfo::Tcp { source_port, .. } => source_port,
        };
        SocketAddr::new(self.ip.source_ip(), source_port)
    }

    fn build_response_packet(
        &self,
        dns_response: &[u8],
        response_packet: &mut [u8],
    ) -> Result<usize, String> {
        let payload_header = match self.payload {
            PayloadRequestInfo::Udp { .. } => UDP_HEADER,
            PayloadRequestInfo::Tcp { .. } => TCP_MIN_HEADER,
        };
        let ip_header_length =
            self.build_ip_header(payload_header + dns_response.len(), response_packet)?;

        self.build_payload(ip_header_length, dns_response, response_packet)
    }

    fn build_ip_header(
        &self,
        payload_length: usize,
        response_packet: &mut [u8],
    ) -> Result<usize, String> {
        match &self.ip {
            IpRequestInfo::V4 {
                source_ip,
                destination_ip,
                dscp,
                ecn,
                ttl,
                identification,
            } => {
                let mut ip_response = MutableIpv4Packet::new(response_packet).ok_or_else(|| {
                    String::from("Failed to build MutableIpv4Packet for response packet")
                })?;

                ip_response.set_version(4);
                ip_response.set_header_length((IPV4_HEADER / 4) as u8);
                ip_response.set_dscp(*dscp);
                ip_response.set_ecn(*ecn);
                ip_response.set_total_length((IPV4_HEADER + payload_length) as u16);
                ip_response.set_flags(2);
                ip_response.set_identification(*identification);
                match self.payload {
                    PayloadRequestInfo::Udp { .. } => {
                        ip_response.set_next_level_protocol(IpNextHeaderProtocols::Udp)
                    }
                    PayloadRequestInfo::Tcp { .. } => {
                        ip_response.set_next_level_protocol(IpNextHeaderProtocols::Tcp)
                    }
                }
                ip_response.set_ttl(*ttl);
                ip_response.set_source(*destination_ip);
                ip_response.set_destination(*source_ip);
                ip_response.set_checksum(0);
                ip_response.set_checksum(checksum(&ip_response.to_immutable()));

                telio_log_debug!("IP response: {:?}", &ip_response);
                Ok(IPV4_HEADER)
            }
            IpRequestInfo::V6 {
                source_ip,
                destination_ip,
            } => {
                let mut ip_response = MutableIpv6Packet::new(response_packet).ok_or_else(|| {
                    String::from("Failed to build MutableIpv6Packet for response packet")
                })?;

                ip_response.set_version(6);
                ip_response.set_traffic_class(0);
                ip_response.set_flow_label(0);
                ip_response.set_payload_length(payload_length as u16);
                match self.payload {
                    PayloadRequestInfo::Udp { .. } => {
                        ip_response.set_next_header(IpNextHeaderProtocols::Udp)
                    }
                    PayloadRequestInfo::Tcp { .. } => {
                        ip_response.set_next_header(IpNextHeaderProtocols::Tcp)
                    }
                }
                ip_response.set_next_header(IpNextHeaderProtocols::Udp);
                ip_response.set_hop_limit(255);
                ip_response.set_source(*destination_ip);
                ip_response.set_destination(*source_ip);

                telio_log_debug!("IP response: {:?}", &ip_response);
                Ok(IPV6_HEADER)
            }
        }
    }

    fn build_payload(
        &self,
        ihl: usize,
        dns_response: &[u8],
        response_packet: &mut [u8],
    ) -> Result<usize, String> {
        match self.payload {
            PayloadRequestInfo::Udp {
                source_port,
                destination_port,
                ..
            } => {
                let length = ihl + UDP_HEADER + dns_response.len();
                let buffer_slice = response_packet
                    .get_mut(ihl..length)
                    .ok_or_else(|| String::from("Out of bounds on response packet buffer"))?;

                let mut udp_response = MutableUdpPacket::new(buffer_slice).ok_or_else(|| {
                    String::from("Failed to build MutableUdpPacket for response packet")
                })?;

                udp_response.set_source(destination_port);
                udp_response.set_destination(source_port);
                udp_response.set_length((UDP_HEADER + dns_response.len()) as u16);
                udp_response.set_payload(dns_response);
                udp_response.set_checksum(0);
                udp_response
                    .set_checksum(self.ip.compute_udp_checksum(&udp_response.to_immutable()));

                telio_log_debug!("UDP response: {:?}", &udp_response);
                Ok(length)
            }
            PayloadRequestInfo::Tcp {
                source_port,
                destination_port,
                next_sequence,
            } => {
                let length = ihl + TCP_MIN_HEADER;
                let buffer_slice = response_packet
                    .get_mut(ihl..length)
                    .ok_or_else(|| String::from("Out of bounds on response packet buffer"))?;
                let mut tcp_response = MutableTcpPacket::new(buffer_slice).ok_or_else(|| {
                    String::from("Failed to build MutableTcpPacket for response packet")
                })?;

                tcp_response.set_source(source_port);
                tcp_response.set_destination(destination_port);
                tcp_response.set_sequence(next_sequence);
                tcp_response.set_flags(TcpFlags::RST);
                tcp_response.set_checksum(0);
                let checksum = match self.ip {
                    IpRequestInfo::V4 {
                        source_ip,
                        destination_ip,
                        ..
                    } => pnet_packet::tcp::ipv4_checksum(
                        &tcp_response.to_immutable(),
                        &source_ip,
                        &destination_ip,
                    ),
                    IpRequestInfo::V6 {
                        source_ip,
                        destination_ip,
                    } => pnet_packet::tcp::ipv6_checksum(
                        &tcp_response.to_immutable(),
                        &source_ip,
                        &destination_ip,
                    ),
                };
                tcp_response.set_checksum(checksum);

                telio_log_debug!("UDP response: {:?}", &tcp_response);
                Ok(length)
            }
        }
    }
}

trait IpPacket<'a>: Sized + Packet {
    fn try_from(buffer: &'a [u8]) -> Option<Self>;
    fn ip_request_info(&self) -> IpRequestInfo;
    fn udp_checksum(&self, udp_packet: &UdpPacket<'_>) -> u16;
    fn check_valid(&self) -> bool;
    fn next_level_protocol(&self) -> IpNextHeaderProtocol;
}

impl<'a> IpPacket<'a> for Ipv4Packet<'a> {
    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn ip_request_info(&self) -> IpRequestInfo {
        IpRequestInfo::V4 {
            source_ip: self.get_source(),
            destination_ip: self.get_destination(),
            dscp: self.get_dscp(),
            ecn: self.get_ecn(),
            ttl: self.get_ttl(),
            identification: self.get_identification(),
        }
    }

    fn udp_checksum(&self, udp_packet: &UdpPacket<'_>) -> u16 {
        ipv4_checksum(udp_packet, &self.get_source(), &self.get_destination())
    }

    fn check_valid(&self) -> bool {
        if self.get_version() != 4 {
            return false; // Non IPv4
        }
        if self.get_header_length() < 5 {
            return false; // IPv4->IHL < 5
        }
        if checksum(self) != self.get_checksum() {
            return false; // Invalid checksum
        }
        true
    }

    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }
}

impl<'a> IpPacket<'a> for Ipv6Packet<'a> {
    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn ip_request_info(&self) -> IpRequestInfo {
        IpRequestInfo::V6 {
            source_ip: self.get_source(),
            destination_ip: self.get_destination(),
        }
    }

    fn udp_checksum(&self, udp_packet: &UdpPacket<'_>) -> u16 {
        ipv6_checksum(udp_packet, &self.get_source(), &self.get_destination())
    }

    fn check_valid(&self) -> bool {
        if self.get_version() != 6 {
            return false; // Non IPv6
        }
        if self.get_payload_length() as usize != self.payload().len() {
            return false;
        }
        true
    }

    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }
}

#[async_trait]
trait WithZones {
    async fn zones(&self) -> Arc<ClonableZones>;
    async fn zones_mut(&self) -> RwLockMappedWriteGuard<ClonableZones>;
}

#[async_trait]
impl WithZones for Arc<RwLock<LocalNameServer>> {
    async fn zones(&self) -> Arc<ClonableZones> {
        self.read().await.zones.clone()
    }

    async fn zones_mut(&self) -> RwLockMappedWriteGuard<ClonableZones> {
        RwLockWriteGuard::map(self.write().await, |this| Arc::make_mut(&mut this.zones))
    }
}

#[async_trait]
impl NameServer for Arc<RwLock<LocalNameServer>> {
    async fn upsert(
        &self,
        zone: &str,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<(), String> {
        let azone = Arc::new(AuthoritativeZone::new(zone, records, ttl_value).await?);

        self.zones_mut()
            .await
            .upsert(LowerName::from_str(zone)?, Box::new(azone));
        Ok(())
    }

    async fn forward(&self, to: &[IpAddr]) -> Result<(), String> {
        self.zones_mut().await.upsert(
            LowerName::from_str(".")?,
            Box::new(Arc::new(ForwardZone::new(".", to).await?)),
        );
        Ok(())
    }

    // TODO: maybe report or recover in case of thread panic
    async fn stop(&self) {
        if let Some(handle) = &self.read().await.task_handle {
            handle.abort();
        }
    }

    #[allow(clippy::unwrap_used)]
    async fn start(&self, peer: Arc<Mutex<Tunn>>, socket: Arc<UdpSocket>) {
        let nameserver = self.clone();
        self.write().await.task_handle = Some(tokio::spawn(LocalNameServer::dns_service(
            peer, nameserver, socket,
        )));
        telio_log_trace!("start_sucessfull");
    }
}

#[cfg(test)]
mod tests {
    use crate::zone::Records;
    use hickory_server::{
        authority::MessageRequest,
        proto::{
            op::{Message, Query},
            rr::Name,
            serialize::binary::{BinDecodable, BinDecoder, BinEncodable},
        },
        server::Request,
    };
    use std::{net::Ipv4Addr, str::FromStr};

    use super::*;

    fn dns_request(host: String) -> Request {
        let mut question = Message::new();
        let mut query = Query::new();
        query.set_name(Name::from_str(&host).unwrap());
        question.add_query(query);
        let message_request = MessageRequest::from_bytes(&question.to_bytes().unwrap()).unwrap();

        Request::new(
            message_request,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            Protocol::Udp,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn dns_lookup() {
        let entry_name = String::from("pashka.nord.");
        let mut records = Records::new();
        records.insert(
            entry_name.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(100, 69, 69, 69))],
        );
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        nameserver
            .upsert("nord", &records, TtlValue(60))
            .await
            .unwrap();
        let request = dns_request(entry_name.clone());
        let resolver = Resolver::new();
        nameserver
            .zones()
            .await
            .lookup(&request, resolver.clone())
            .await
            .unwrap();
        let buf = resolver.0.lock().await;
        let mut decoder = BinDecoder::new(&buf);
        let answers = Message::read(&mut decoder).unwrap().take_answers();
        assert_eq!(answers.len(), 1);
        assert_ne!(
            answers
                .iter()
                .find(|&answer| answer.name().to_string() == entry_name),
            None
        );
    }

    #[tokio::test]
    async fn zones_are_lazily_copied_on_write_access() {
        let name1 = "test.nord.".to_owned();
        let mut records = Records::new();
        records.insert(
            name1.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(100, 69, 69, 69))],
        );
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        let raw_read_ptr1 = Arc::as_ptr(&nameserver.zones().await);
        nameserver
            .upsert("nord", &records, TtlValue(60))
            .await
            .unwrap();
        let raw_read_ptr2 = Arc::as_ptr(&nameserver.zones().await);
        assert_eq!(raw_read_ptr1, raw_read_ptr2);

        let name2 = "test.nord2.".to_owned();
        let mut records = Records::new();
        records.insert(
            name2.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(100, 69, 69, 69))],
        );

        let read_ptr3 = nameserver.zones().await;
        nameserver
            .upsert("nord2", &records, TtlValue(60))
            .await
            .unwrap();
        let raw_read_ptr4 = Arc::as_ptr(&nameserver.zones().await);
        assert_ne!(Arc::as_ptr(&read_ptr3), raw_read_ptr4);

        let zones = nameserver.zones().await;
        assert!(zones.contains(&LowerName::from_str("nord").unwrap()));
        assert!(zones.contains(&LowerName::from_str("nord2").unwrap()));
    }

    #[tokio::test]
    async fn forward_zones_are_cloned_too() {
        let name1 = "test.nord.".to_owned();
        let mut records = Records::new();
        records.insert(
            name1.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(100, 69, 69, 69))],
        );
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        nameserver
            .upsert("nord.", &records, TtlValue(60))
            .await
            .unwrap();

        let zones = nameserver.zones().await;
        assert!(zones.contains(&LowerName::from_str(".").unwrap()));
        assert!(zones.contains(&LowerName::from_str("nord").unwrap()));
    }
}
