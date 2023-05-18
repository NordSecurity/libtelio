use crate::{
    resolver::Resolver,
    zone::{AuthoritativeZone, ClonableZones, ForwardZone, Records},
};
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    udp::{ipv4_checksum, MutableUdpPacket, UdpPacket},
    Packet,
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, RwLockMappedWriteGuard, RwLockWriteGuard, Semaphore};
use tokio::task::JoinHandle;
use trust_dns_client::rr::LowerName;
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::server::{Protocol, Request};

use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};

const IP_HEADER: usize = 20; // bytes
const MAX_PACKET: usize = 2048;
const UDP_HEADER: usize = 8;
const MAX_CONCURRENT_QUERIES: usize = 256;

/// NameServer is a server that stores the DNS records.
#[async_trait]
pub trait NameServer {
    /// Start the server.
    ///
    /// Server will listen on `socket`, expect connections from `peer` and will
    /// reply to `dst_address`.
    async fn start(&self, peer: Arc<Tunn>, socket: Arc<UdpSocket>, dst_address: SocketAddr);
    /// Stop the server.
    async fn stop(&self);
    /// Configure list of forward DNS servers for zone '.'.
    async fn forward(&self, to: &[IpAddr]) -> Result<(), String>;
    /// Insert or update zone records used by the server.
    async fn upsert(&self, zone: &str, records: &Records) -> Result<(), String>;
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
    async fn upsert(&self, zone: &str, records: &Records) -> Result<(), String> {
        self.zones_mut().await.upsert(
            LowerName::from_str(zone)?,
            Box::new(Arc::new(AuthoritativeZone::new(zone, records).await?)),
        );
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

    #[allow(unwrap_check)]
    async fn start(&self, peer: Arc<Tunn>, socket: Arc<UdpSocket>, dst_address: SocketAddr) {
        let nameserver = self.clone();
        self.write().await.task_handle = Some(tokio::spawn(async move {
            let mut receiving_buffer = vec![0u8; MAX_PACKET];
            let mut sending_buffer = vec![0u8; MAX_PACKET];
            let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
            loop {
                let bytes_read = match socket.recv(&mut receiving_buffer).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        telio_log_error!("[DNS] Failed to read bytes: {:?}", e);
                        continue;
                    }
                };

                loop {
                    match peer.update_timers(&mut sending_buffer) {
                        TunnResult::WriteToNetwork(packet) => {
                            if let Err(e) = socket.send_to(packet, dst_address).await {
                                telio_log_warn!(
                                    "[DNS] Failed to send timer update packet : {:?}",
                                    e
                                )
                            };
                        }
                        TunnResult::Err(e) => {
                            telio_log_error!("[DNS] Failed to update Tunn timers : {:?}", e);
                            break;
                        }
                        _ => break,
                    };
                }

                let peer = peer.clone();
                let socket = socket.clone();
                let nameserver = nameserver.clone();
                let mut receiving_buffer = receiving_buffer.clone();
                let mut sending_buffer = sending_buffer.clone();
                let semaphore = semaphore.clone();
                tokio::spawn(async move {
                    match peer.decapsulate(
                        None,
                        &receiving_buffer[..bytes_read],
                        &mut sending_buffer,
                    ) {
                        // Handshake packets
                        TunnResult::WriteToNetwork(packet) => {
                            if let Err(e) = socket.send_to(packet, dst_address).await {
                                telio_log_warn!("[DNS] Failed to send handshake packet  : {:?}", e);
                                return;
                            };
                            let mut temporary_buffer = [0u8; MAX_PACKET];

                            while let TunnResult::WriteToNetwork(empty) =
                                peer.decapsulate(None, &[], &mut temporary_buffer)
                            {
                                if let Err(e) = socket.send_to(empty, dst_address).await {
                                    telio_log_warn!(
                                        "[DNS] Failed to send handshake packet  : {:?}",
                                        e
                                    );
                                    return;
                                };
                            }
                        }
                        // DNS packets
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            // !
                            let _lease = match semaphore.try_acquire() {
                                Ok(lease) => lease,
                                Err(_) => {
                                    telio_log_debug!("Error semaphore.try_acquire()");
                                    return;
                                }
                            };

                            let ip_request = match Ipv4Packet::new(packet) {
                                Some(request) => request,
                                None => {
                                    telio_log_debug!("ip_request NULL");
                                    return;
                                }
                            };

                            // Validate IP checksum
                            if checksum(&ip_request) != ip_request.get_checksum() {
                                telio_log_debug!("Invalid IP checksum");
                                return;
                            }

                            let udp_request = match UdpPacket::new(ip_request.payload()) {
                                Some(request) => request,
                                None => {
                                    telio_log_debug!("udp_request NULL");
                                    return;
                                }
                            };

                            // Validate UDP checksum
                            let computed_udp_checksum = ipv4_checksum(
                                &udp_request,
                                &ip_request.get_source(),
                                &ip_request.get_destination(),
                            );
                            if computed_udp_checksum != udp_request.get_checksum() {
                                telio_log_debug!("Invalid UDP checksum");
                                return;
                            }

                            // Validate DNS port
                            if udp_request.get_destination() != 53 {
                                telio_log_debug!("Invalid DNS port");
                                return;
                            }

                            let dns_request =
                                match MessageRequest::from_bytes(udp_request.payload()) {
                                    Ok(request) => request,
                                    Err(_) => {
                                        telio_log_debug!("Error : dns_request");
                                        return;
                                    }
                                };

                            let resolver = Resolver::new();
                            let zones = nameserver.zones().await;
                            let dns_request = Request::new(
                                dns_request,
                                SocketAddr::new(
                                    ip_request.get_source().into(),
                                    udp_request.get_source(),
                                ),
                                Protocol::Udp,
                            );
                            zones.lookup(&dns_request, resolver.clone()).await;

                            telio_log_debug!("dns request :{:?}", &dns_request);

                            let dns_response = resolver.0.lock().await;
                            let length = IP_HEADER + UDP_HEADER + dns_response.len();

                            if let Some(mut ip_response) =
                                MutableIpv4Packet::new(&mut receiving_buffer)
                            {
                                ip_response.set_version(4);
                                ip_response.set_header_length((IP_HEADER / 4) as u8);
                                ip_response.set_dscp(ip_request.get_dscp());
                                ip_response.set_ecn(ip_request.get_ecn());
                                ip_response.set_total_length(length as u16);
                                ip_response.set_flags(2);
                                ip_response.set_identification(ip_request.get_identification());
                                ip_response.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                                ip_response.set_ttl(ip_request.get_ttl());
                                ip_response.set_source(ip_request.get_destination());
                                ip_response.set_destination(ip_request.get_source());
                                ip_response.set_checksum(0);
                                ip_response.set_checksum(checksum(&ip_response.to_immutable()));

                                telio_log_debug!("Ip response: {:?}", &ip_response);
                            } else {
                                telio_log_debug!("Failed to create mutable IPv4 packet");
                                return;
                            }

                            telio_log_debug!("nameserver response: {:?}", &dns_response);

                            if let Some(mut udp_response) =
                                MutableUdpPacket::new(&mut receiving_buffer[IP_HEADER..length])
                            {
                                udp_response.set_source(udp_request.get_destination());
                                udp_response.set_destination(udp_request.get_source());
                                udp_response.set_length((UDP_HEADER + dns_response.len()) as u16);
                                udp_response.set_payload(&dns_response);
                                udp_response.set_checksum(ipv4_checksum(
                                    &udp_response.to_immutable(),
                                    &ip_request.get_destination(),
                                    &ip_request.get_source(),
                                ));

                                telio_log_debug!("usp response:  : {:?}", &udp_response);
                            } else {
                                telio_log_debug!("Failed to create mutable UDP packet");
                                return;
                            }
                            match peer.encapsulate(&receiving_buffer[..length], &mut sending_buffer)
                            {
                                TunnResult::WriteToNetwork(dns) => {
                                    if let Err(e) = socket.send_to(dns, dst_address).await {
                                        telio_log_warn!(
                                            "[DNS] Failed to send DNS query response  {:?}",
                                            e
                                        )
                                    };
                                }
                                TunnResult::Err(e) => {
                                    telio_log_warn!(
                                        "[DNS] Failed to encapsulate DNS query response  {:?}",
                                        e
                                    )
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                });
            }
        }));

        telio_log_trace!("start_sucessfull");
    }
}

#[cfg(test)]
mod tests {
    use crate::zone::Records;
    use std::{net::Ipv4Addr, str::FromStr};
    use trust_dns_client::rr::Name;
    use trust_dns_proto::{
        op::{Message, Query},
        serialize::binary::{BinDecodable, BinDecoder, BinEncodable},
    };
    use trust_dns_server::authority::MessageRequest;
    use trust_dns_server::server::Request;

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
        records.insert(entry_name.clone(), Ipv4Addr::new(100, 69, 69, 69));
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        nameserver.upsert("nord", &records).await.unwrap();
        let request = dns_request(entry_name.clone());
        let resolver = Resolver::new();
        nameserver
            .zones()
            .await
            .lookup(&request, resolver.clone())
            .await;
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
        records.insert(name1.clone(), Ipv4Addr::new(100, 69, 69, 69));
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        let raw_read_ptr1 = Arc::as_ptr(&nameserver.zones().await);
        nameserver.upsert("nord", &records).await.unwrap();
        let raw_read_ptr2 = Arc::as_ptr(&nameserver.zones().await);
        assert_eq!(raw_read_ptr1, raw_read_ptr2);

        let name2 = "test.nord2.".to_owned();
        let mut records = Records::new();
        records.insert(name2.clone(), Ipv4Addr::new(100, 69, 69, 69));

        let read_ptr3 = nameserver.zones().await;
        nameserver.upsert("nord2", &records).await.unwrap();
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
        records.insert(name1.clone(), Ipv4Addr::new(100, 69, 69, 69));
        let nameserver = LocalNameServer::new(&[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
            .await
            .unwrap();
        nameserver.upsert("nord.", &records).await.unwrap();

        let zones = nameserver.zones().await;
        assert!(zones.contains(&LowerName::from_str(".").unwrap()));
        assert!(zones.contains(&LowerName::from_str("nord").unwrap()));
    }
}
