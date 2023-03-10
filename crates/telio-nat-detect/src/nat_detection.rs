//! Nat detection component used to build up statistics related with NAT types.

// imports
use nat_detect::{nat_detect, NatType};
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Detected NAT parameters.
pub struct NatData {
    /// public address on internet
    pub public_ip: SocketAddr,
    /// Nat Type ( full cone, etc.)
    pub nat_type: NatType,
}

/// Perform a NAT discover operation over a single stun server.
///
/// # Example
///
/// ```rust
/// # use telio_nat_detect::nat_detection::{NatData,retrieve_single_nat};
/// # fn get_my_stun_server_ip() -> String { "10.2.3.4".to_owned() }
/// # #[tokio::main]
/// # async fn main() {
/// match retrieve_single_nat(get_my_stun_server_ip()).await {
///     Ok(NatData{public_ip,nat_type}) => {
///         println!("our public ip is {} and the nat type is {:?}", public_ip, nat_type);
///     },
///     Err(e) => {
///         eprintln!("Failed to detect nat parameters due to: {}", e);
///     }
/// }
/// # }
/// ```
pub async fn retrieve_single_nat(stun_sever_ip: String) -> Result<NatData, Error> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    match nat_detect(address, &stun_sever_ip).await {
        Ok(data) => {
            // converting the result in a better
            // way to show
            let result = NatData {
                public_ip: data.1,
                nat_type: data.2,
            };
            Ok(result)
        }

        Err(no_data) => Err(no_data),
    }
}
