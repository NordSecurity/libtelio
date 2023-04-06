use crate::endpoint_providers::{EndpointCandidate, Error as EpError};
use async_trait::async_trait;
use http::Uri;
use httparse::{Response, EMPTY_HEADER};
use ipnet::Ipv4Net;
use rupnp::Device;
use rupnp::Service;
use ssdp_client::{SearchTarget, URN};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use telio_sockets::External;
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};
use telio_wg::WireGuard;
use tokio::net::UdpSocket;

#[cfg(test)]
use mockall::automock;

macro_rules! UPNP_ROUTE_REQUEST_FORMAT {
    () => {
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort>\
<NewProtocol>UDP</NewProtocol><NewInternalPort>{}</NewInternalPort><NewInternalClient>{}\
</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>libminiupnpc\
</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>"
    };
}

macro_rules! UPNP_DELETE_CHECK_ROUTE_REQUEST {
    () => {"<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>"};
}

const INSUFFICIENT_BUFFER_MSG: &str = "buffer size too small, udp packets lost";
const RENDERING_CONTROL: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
const SEARCH_TARGET: SearchTarget = SearchTarget::URN(RENDERING_CONTROL);
const MX: usize = 3;
const ROUTE_TIMEOUT_SECONDS: u16 = 60 * 60;
const GET_INTERFACE_TIMEOUT: u64 = 2;

#[derive(Default, Clone, Copy)]
pub struct PortMapping {
    pub internal: u16,
    pub external: u16,
}

pub async fn get_igd_device(
    sock: Arc<External<UdpSocket>>,
) -> Result<(Device, IpAddr), rupnp::Error> {
    let broadcast_address: SocketAddr = ([239, 255, 255, 250], 1900).into();
    let ssdp_request_msg = format!(
        "M-SEARCH * HTTP/1.1\r
Host:239.255.255.250:1900\r
Man:\"ssdp:discover\"\r
ST: {}\r
MX: {}\r\n\r\n",
        SEARCH_TARGET, MX
    );
    sock.send_to(ssdp_request_msg.as_bytes(), &broadcast_address)
        .await?;

    let mut buf = vec![0u8; 2048];
    let (location, addr) = loop {
        let (_len, addr) = match sock.recv_from(&mut buf).await {
            Ok((len, _addr)) if len == 2048 => {
                telio_log_warn!("{}", INSUFFICIENT_BUFFER_MSG);
                continue;
            }
            Ok((len, addr)) => {
                telio_log_info!("Got SSDP response from address {}", addr);
                (std::str::from_utf8(&buf[..len])?, addr.ip())
            }
            Err(_e) => {
                continue;
            }
        };

        let mut headers = [EMPTY_HEADER; 16];
        let mut response = Response::new(&mut headers);

        if let Some(loc) = response
            .parse(&buf)
            .ok()
            .and_then(|_| response.headers.iter().find(|&h| h.name == "LOCATION"))
        {
            break (*loc, addr);
        }
    };

    let uri = str::from_utf8(location.value)?;

    let device = Device::from_url(uri.parse()?).await?;
    Ok((device, addr))
}

/// Get interface's IP that was used to access an IGD device
fn get_my_local_endpoints(igd_ip: Ipv4Addr) -> std::result::Result<IpAddr, EpError> {
    let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)?;
    let igd_subnet: Ipv4Net = Ipv4Net::new(igd_ip, 16)?;

    if_addrs::get_if_addrs()?
        .iter()
        .find_map(|ip| {
            if ip.addr.is_loopback() {
                return None;
            }
            match ip.addr.ip() {
                IpAddr::V4(v4) => {
                    if shared_range.contains(&v4) && !igd_subnet.contains(&v4) {
                        return None;
                    }
                }
                // Filter IPv6
                _ => return None,
            }
            Some(ip.addr.ip())
        })
        .ok_or(EpError::NoMatchingLocalEndpoint)
}

#[async_trait]
#[cfg_attr(test, automock)]
pub trait IgdCommands: Send + Sync + Default + 'static {
    /// Create or return an existing Upnp endpoint
    async fn add_endpoint(
        &self,
        ip_addr: IpAddr,
        proxy_mapping: PortMapping,
        wg_mapping: PortMapping,
    ) -> Result<EndpointCandidate, EpError>;
    /// Command to add/delete or check an existing Upnp route on IGD device
    async fn igd_service_command(
        &self,
        command_type: ServiceCmdType,
        port_map: PortMapping,
        ipaddr: IpAddr,
    ) -> Result<(), EpError>;
    /// Prepare add/delete/check route Upnp request for IGD device
    fn prepare_service_command(
        &self,
        command_type: ServiceCmdType,
        port_map: PortMapping,
        ipaddr: IpAddr,
    ) -> Result<(Service, String, String), EpError>;
    /// Get external IP from IGD device
    async fn get_external_ip(&self) -> Result<IpAddr, EpError>;
    /// Check and retrieve information on Upnp service from IGD device
    async fn get_igd(&mut self, udp_socket: Arc<External<UdpSocket>>) -> Result<IpAddr, EpError>;
    /// Use to port from wireguard interface ( This function needed for Upnp unit tests )
    async fn get_wg_interface_port(&self, wg: Arc<dyn WireGuard>) -> Option<u16>;
}

#[derive(PartialEq, Eq)]
pub enum ServiceCmdType {
    AddRoute,
    DeleteRoute,
    CheckRoute,
}

#[derive(Default, Debug, Clone)]
pub struct Igd {
    device_url: Uri,
    service: Option<Service>,
}

#[async_trait]
impl IgdCommands for Igd {
    // This function exist in IgdCommands only for Upnp module unit tests
    // Get port number associated with wireguard socket
    async fn get_wg_interface_port(&self, wireguard: Arc<dyn WireGuard>) -> Option<u16> {
        match wireguard
            .wait_for_listen_port(Duration::from_secs(GET_INTERFACE_TIMEOUT))
            .await
        {
            Ok(port) => Some(port),
            Err(e) => {
                telio_log_debug!("Failed to get wireguard interface port: {}", e);
                None
            }
        }
    }

    fn prepare_service_command(
        &self,
        command_type: ServiceCmdType,
        port_map: PortMapping,
        ipaddr: IpAddr,
    ) -> Result<(Service, String, String), EpError> {
        let (args, command) = match command_type {
            ServiceCmdType::AddRoute => (
                format!(
                    UPNP_ROUTE_REQUEST_FORMAT!(),
                    &port_map.external, &port_map.internal, ipaddr, ROUTE_TIMEOUT_SECONDS
                ),
                "AddPortMapping".to_string(),
            ),
            ServiceCmdType::DeleteRoute => (
                format!(UPNP_DELETE_CHECK_ROUTE_REQUEST!(), port_map.internal),
                "DeletePortMapping".to_string(),
            ),
            ServiceCmdType::CheckRoute => (
                format!(UPNP_DELETE_CHECK_ROUTE_REQUEST!(), port_map.internal),
                "GetSpecificPortMappingEntry".to_string(),
            ),
        };

        let service = match &self.service {
            Some(serv) => serv,
            None => return Err(EpError::FailedToGetUpnpService),
        };

        Ok((service.clone(), command, args))
    }

    async fn igd_service_command(
        &self,
        command_type: ServiceCmdType,
        port_map: PortMapping,
        ipaddr: IpAddr,
    ) -> Result<(), EpError> {
        let (service, command, args) =
            self.prepare_service_command(command_type, port_map, ipaddr)?;

        match service.action(&self.device_url, &command, &args).await {
            Ok(_) => Ok(()),
            Err(e) => Err(EpError::UpnpError(e)),
        }
    }

    async fn add_endpoint(
        &self,
        ip_addr: IpAddr,
        proxy_mapping: PortMapping,
        wg_mapping: PortMapping,
    ) -> Result<EndpointCandidate, EpError> {
        self.igd_service_command(ServiceCmdType::AddRoute, wg_mapping, ip_addr)
            .await?;
        self.igd_service_command(ServiceCmdType::AddRoute, proxy_mapping, ip_addr)
            .await?;

        let ext_ip = self.get_external_ip().await?;

        Ok(EndpointCandidate {
            wg: SocketAddr::new(ext_ip, wg_mapping.external),
            udp: SocketAddr::new(ext_ip, proxy_mapping.external),
        })
    }

    async fn get_external_ip(&self) -> Result<IpAddr, EpError> {
        let mut curr_err = EpError::FailedToGetUpnpService;

        let service = match &self.service {
            Some(serv) => serv,
            None => return Err(EpError::FailedToGetUpnpService),
        };
        // Try to get external ip
        for _n in 1..5 {
            match service
                .action(&self.device_url, "GetExternalIPAddress", "")
                .await
            {
                Ok(resp) => {
                    if let Some(ip) = resp.get("NewExternalIPAddress") {
                        match ip.parse() {
                            Ok(ip_addr) => return Ok(ip_addr),
                            Err(e) => curr_err = EpError::AddressParseError(e),
                        };
                    }
                }
                Err(e) => curr_err = EpError::UpnpError(e),
            }
        }
        Err(curr_err)
    }

    async fn get_igd(&mut self, udp_socket: Arc<External<UdpSocket>>) -> Result<IpAddr, EpError> {
        match Box::pin(get_igd_device(udp_socket)).await {
            Ok((device, addr)) => {
                self.service = match device.find_service(&RENDERING_CONTROL).as_ref() {
                    Some(&serv) => Some(serv.clone()),
                    None => {
                        return Err(EpError::FailedToGetUpnpService);
                    }
                };
                self.device_url = device.url().clone();

                let igd_ip = match addr {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_e) => return Err(EpError::FailedToGetUpnpService), // should not reach this line
                };

                get_my_local_endpoints(igd_ip)
            }
            Err(e) => Err(EpError::UpnpError(e)),
        }
    }
}
