use httparse::{parse_headers, Response, EMPTY_HEADER};
use rupnp::Device;
use ssdp_client::{Error, SearchTarget, URN};
use std::net::{IpAddr, SocketAddr};
use std::str;
use std::sync::Arc;
use telio_sockets::External;
use telio_utils::{telio_log_info, telio_log_warn};
use tokio::net::UdpSocket;

const INSUFFICIENT_BUFFER_MSG: &str = "buffer size too small, udp packets lost";
const RENDERING_CONTROL: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
const SEARCH_TARGET: SearchTarget = SearchTarget::URN(RENDERING_CONTROL);
const MX: usize = 3;

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

    let mut buf = [0u8; 2048];
    loop {
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

        let location: &[u8] = match response.parse(&buf) {
            Ok(_size) => match response.headers.iter().find(|&h| h.name == "LOCATION") {
                Some(loc) => loc.value,
                None => continue,
            },
            Err(_e) => {
                continue;
            }
        };
        let uri = match str::from_utf8(location) {
            Ok(str) => str,
            Err(_e) => {
                continue;
            }
        };
        let device = Device::from_url(uri.parse()?).await?;
        break Ok((device, addr));
    }
}
