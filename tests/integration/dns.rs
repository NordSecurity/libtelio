use std::net::{IpAddr, Ipv4Addr};

use std::time::Duration;

use futures::FutureExt;
use systests::derp::Derp;
use systests::dns::{Dns, DnsConfig, DnsError};
use systests::test_device::TestDevice;
use systests::utils::interface_helper::InterfaceHelper;

use telio_model::features::PathType;
use tokio::runtime::Runtime;

const GOOGLE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

#[test]
fn test_poc_dns() {
    let rt = Runtime::new().unwrap();
    let fut = async {
        let mut ifc_helper = InterfaceHelper::new();
        let derp = Derp::start().await;
        let dns_config = DnsConfig::default().add_ip("google.com", GOOGLE_IP);
        let dns = Dns::start(dns_config).await;

        let test_res = tokio::task::spawn(async move {
            let mut clients =
                TestDevice::generate_clients(vec!["alpha", "beta"], &mut ifc_helper).await;

            let mut alpha = clients.remove("alpha").unwrap();
            let mut beta = clients.remove("beta").unwrap();

            alpha.start().await;
            beta.start().await;

            alpha.configure_dns_route();

            alpha.set_meshnet_config(&[&beta]).await;
            beta.set_meshnet_config(&[&alpha]).await;

            alpha
                .wait_for_connection_peer(
                    beta.peer.public_key,
                    &[PathType::Direct, PathType::Relay],
                )
                .await
                .unwrap();
            beta.wait_for_connection_peer(
                alpha.peer.public_key,
                &[PathType::Direct, PathType::Relay],
            )
            .await
            .unwrap();

            assert!(matches!(
                alpha.query_dns("google.com", GOOGLE_IP).await.unwrap_err(),
                DnsError::Timeout(_),
            ));

            alpha.enable_magic_dns(vec!["127.64.0.2"]).await;
            alpha.query_dns("google.com", GOOGLE_IP).await.unwrap();
            alpha.query_dns("beta.nord", beta.ip).await.unwrap();
            alpha.query_dns("alpha.nord", alpha.ip).await.unwrap();

            alpha.disable_magic_dns().await;

            assert!(matches!(
                alpha.query_dns("google.com", GOOGLE_IP).await.unwrap_err(),
                DnsError::Timeout(_),
            ));

            alpha.stop().await;
            alpha.shutdown().await;

            beta.stop().await;
            beta.shutdown().await;

            alpha.kill().await;
            beta.kill().await;
        })
        .catch_unwind()
        .await;

        dns.stop().await;
        derp.stop().await;

        test_res
    };

    rt.block_on(async { tokio::time::timeout(Duration::from_secs(30), fut).await })
        .unwrap()
        .unwrap()
        .unwrap();
}
