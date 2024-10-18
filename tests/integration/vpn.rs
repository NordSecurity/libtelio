use std::panic::AssertUnwindSafe;

use telio_model::{features::PathType, mesh::ExitNode};

use crate::utils::{
    interface_helper::InterfaceHelper,
    test_client::TestClient,
    vpn::{setup_vpn_servers, VpnConfig},
};

#[test]
fn test_poc_vpn() {
    let mut ifc_helper = InterfaceHelper::new();
    let test_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut clients =
            TestClient::generate_clients(vec!["alpha"], &mut ifc_helper, Default::default());
        let mut alpha = clients.remove("alpha").unwrap();
        let vpn_config = VpnConfig::get_config();
        setup_vpn_servers(&[&alpha.peer], &vpn_config);

        alpha.start();

        if !alpha.ifc_configured {
            InterfaceHelper::configure_ifc(&alpha.ifc_name, alpha.ip);
            InterfaceHelper::create_vpn_route(&alpha.ifc_name);
            alpha.ifc_configured = true;
        }

        let node = ExitNode {
            identifier: "wgserver".to_owned(),
            public_key: vpn_config.key.public(),
            allowed_ips: None,
            endpoint: Some(
                format!("{}:{}", vpn_config.ip, vpn_config.port)
                    .parse()
                    .expect("Should be valid"),
            ),
        };
        alpha.connect_to_exit_node(&node);

        alpha
            .wait_for_connection_peer(
                vpn_config.key.public(),
                &[PathType::Relay, PathType::Direct],
            )
            .unwrap();

        // stun should return VPN IP

        alpha.stop();
        alpha.shutdown();
    }));
    match test_result {
        Ok(()) => println!("test_vpn_poc passed\n\n"),
        Err(e) => println!("test_vpn_poc failed with error {e:?}\n\n"),
    };
}
