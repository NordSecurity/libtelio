use std::time::Duration;

use futures::FutureExt;
use systests::{derp::Derp, test_device::TestDevice, utils::interface_helper::InterfaceHelper};

use telio_model::features::PathType;
use tokio::runtime::Runtime;

#[test]
fn test_poc_meshnet() {
    let rt = Runtime::new().unwrap();
    let fut = async {
        let mut ifc_helper = InterfaceHelper::new();
        let derp = Derp::start().await;

        let test_res = tokio::task::spawn(async move {
            let mut clients =
                TestDevice::generate_clients(vec!["alpha", "beta"], &mut ifc_helper).await;

            let mut alpha = clients.remove("alpha").unwrap();
            let mut beta = clients.remove("beta").unwrap();

            alpha.start().await;
            beta.start().await;

            alpha.set_meshnet_config(&[&beta]).await;
            beta.set_meshnet_config(&[&alpha]).await;

            alpha
                .wait_for_connection_peer(beta.peer.public_key, &[PathType::Direct])
                .await
                .unwrap();
            beta.wait_for_connection_peer(alpha.peer.public_key, &[PathType::Direct])
                .await
                .unwrap();

            alpha.stop().await;
            alpha.shutdown().await;

            beta.stop().await;
            beta.shutdown().await;

            alpha.kill().await;
            beta.kill().await;
        })
        .catch_unwind()
        .await;

        derp.stop().await;

        test_res
    };

    rt.block_on(async { tokio::time::timeout(Duration::from_secs(30), fut).await })
        .unwrap()
        .unwrap()
        .unwrap();
}
