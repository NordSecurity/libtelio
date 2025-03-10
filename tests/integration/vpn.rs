use std::time::Duration;

use futures::FutureExt;
use telio_model::{features::PathType, mesh::ExitNode};

use systests::{
    test_device::TestDevice,
    utils::{
        interface_helper::InterfaceHelper,
        vpn::{setup_vpn_servers, VpnConfig},
    },
};
use tokio::runtime::Runtime;

#[test]
fn test_poc_vpn() {
    let rt = Runtime::new().unwrap();
    let fut = async {
        let mut ifc_helper = InterfaceHelper::new();

        tokio::task::spawn(async move {
            let mut clients = TestDevice::generate_clients(vec!["alpha"], &mut ifc_helper).await;
            let mut alpha = clients.remove("alpha").unwrap();
            let vpn_config = VpnConfig::get_config();
            setup_vpn_servers(&[&alpha.peer], &vpn_config);

            alpha.start().await;

            InterfaceHelper::create_vpn_route(&alpha.ifc_name);

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
            alpha.connect_to_exit_node(node).await;

            alpha
                .wait_for_connection_peer(
                    vpn_config.key.public(),
                    &[PathType::Relay, PathType::Direct],
                )
                .await
                .unwrap();

            // stun should return VPN IP

            alpha.stop().await;
            alpha.shutdown().await;

            alpha.kill().await;
        })
        .catch_unwind()
        .await
    };

    rt.block_on(async { tokio::time::timeout(Duration::from_secs(30), fut).await })
        .unwrap()
        .unwrap()
        .unwrap();
}
