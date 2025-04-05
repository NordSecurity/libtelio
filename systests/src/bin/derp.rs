use std::sync::Arc;

use dersp::{
    crypto::SecretKey,
    service::{DerpService, Service},
    Config,
};
use tokio::{net::TcpListener, sync::RwLock};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config {
        listen_on: "0.0.0.0:8765".to_owned(),
        mesh_peers: Vec::new(),
        meshkey: Some(SecretKey::gen().public().to_string()),
    };

    let listener = TcpListener::bind(&config.listen_on).await?;
    let service: Arc<RwLock<DerpService>> = DerpService::new(config).await?;

    println!("ready");

    service.run(listener).await?;

    Ok(())
}
