use std::str::FromStr;

use telio_crypto::PublicKey;
use telio_model::config::{RelayState, Server};

pub fn get_derp_servers() -> Vec<Server> {
    vec![Server {
        region_code: "nl".to_owned(),
        name: "Natlab #0001".to_owned(),
        hostname: "derp-01".to_owned(),
        ipv4: "0.0.0.0".parse().unwrap(),
        relay_port: 8765,
        stun_port: 3479,
        stun_plaintext_port: 3478,
        public_key: PublicKey::from_str("qK/ICYOGBu45EIGnopVu+aeHDugBrkLAZDroKGTuKU0=").unwrap(),
        weight: 1,
        use_plain_text: true,
        conn_state: RelayState::Disconnected,
    }]
}
