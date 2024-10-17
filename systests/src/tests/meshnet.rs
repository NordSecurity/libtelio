use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use dersp::{
    service::{DerpService, Service},
    Config,
};
use telio::defaults_builder::FeaturesDefaultsBuilder;

use telio_crypto::SecretKey;
use telio_model::features::PathType;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::level_filters::LevelFilter;

use crate::utils::interface_helper::InterfaceHelper;
use crate::utils::test_client::TestClient;

pub fn test_meshnet_poc() {
    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(std::fs::File::create("tcli.log").unwrap());
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let derp_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _derp_handle = derp_rt.spawn(async move {
        let config = Config {
            listen_on: "0.0.0.0:8765".to_owned(),
            mesh_peers: Vec::new(),
            meshkey: Some(SecretKey::gen().public().to_string()),
        };

        let listener = TcpListener::bind(&config.listen_on).await?;
        let service: Arc<RwLock<DerpService>> = DerpService::new(config).await?;

        service.run(listener).await
    });

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
