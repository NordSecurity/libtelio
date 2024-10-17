use std::net::IpAddr;

use rand::Rng;

pub fn generate_ipv4() -> IpAddr {
    fn rand_range(lower: u8, upper: u8) -> u8 {
        rand::thread_rng().gen_range(lower..=upper)
    }
    format!(
        "100.{}.{}.{}",
        rand_range(64, 127),
        rand_range(0, 255),
        rand_range(8, 254)
    )
    .parse()
    .unwrap()
}
