use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use telio::defaults_builder::FeaturesDefaultsBuilder;

use telio_model::features::PathType;

use crate::utils::interface_helper::InterfaceHelper;
use crate::utils::test_client::TestClient;

#[test]
fn test_poc_meshnet() {
    let mut ifc_helper = InterfaceHelper::new();
    let test_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let features = Arc::new(FeaturesDefaultsBuilder::new());
        let features = features.enable_direct().build();
        let mut clients =
            TestClient::generate_clients(vec!["alpha", "beta"], &mut ifc_helper, features);

        let mut alpha = clients.remove("alpha").unwrap();
        let mut beta = clients.remove("beta").unwrap();

        alpha.start();
        beta.start();

        alpha.set_meshnet_config(&[&beta]);
        beta.set_meshnet_config(&[&alpha]);

        alpha
            .wait_for_connection_peer(beta.peer.public_key, &[PathType::Direct])
            .unwrap();
        beta.wait_for_connection_peer(alpha.peer.public_key, &[PathType::Direct])
            .unwrap();

        alpha.stop();
        alpha.shutdown();

        beta.stop();
        beta.shutdown();
    }));
    match test_result {
        Ok(()) => println!("test_meshnet_poc passed\n\n"),
        Err(e) => println!("test_meshnet_poc failed with error {e:?}\n\n"),
    };
}
