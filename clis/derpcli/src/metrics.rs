#![allow(unwrap_check)]
use anyhow::Result;
use prometheus::{CounterVec, Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use telio_crypto::PublicKey;

#[derive(Clone)]
pub struct Counters {
    pub ping_counter: CounterVec,
    pub pong_counter: CounterVec,
    pub rtt: GaugeVec,
    pub ping_time: GaugeVec,
    pub registry: Registry,
}

#[derive(Clone)]
pub struct Metrics {
    pub clients: HashMap<PublicKey, Counters>,
}

impl Metrics {
    pub fn new() -> Self {
        let clients: HashMap<PublicKey, Counters> = HashMap::new();
        Metrics { clients }
    }

    pub fn add_client(&mut self, client_public_key: PublicKey) -> Result<()> {
        let counters = Counters {
            ping_counter: CounterVec::new(
                Opts::new(
                    "ping_counter",
                    format!("client {} ping_counter", client_public_key,),
                ),
                &["client", "peer"],
            )?,
            pong_counter: CounterVec::new(
                Opts::new(
                    "pong_counter",
                    format!("client {} pong_counter", client_public_key,),
                ),
                &["client", "peer"],
            )?,
            rtt: GaugeVec::new(
                Opts::new(
                    "rtt",
                    format!(
                        "client {} last ping pong round trip time (ms)",
                        client_public_key,
                    ),
                ),
                &["client", "peer"],
            )?,
            ping_time: GaugeVec::new(
                Opts::new(
                    "ping_time",
                    format!("client {} ping time (ms)", client_public_key,),
                ),
                &["client", "peer"],
            )?,
            registry: Registry::new(),
        };

        counters
            .registry
            .register(Box::new(counters.ping_counter.clone()))?;
        counters
            .registry
            .register(Box::new(counters.pong_counter.clone()))?;
        counters.registry.register(Box::new(counters.rtt.clone()))?;
        counters
            .registry
            .register(Box::new(counters.ping_time.clone()))?;

        self.clients.insert(client_public_key, counters);
        Ok(())
    }

    pub fn inc_peer_ping_counter(
        &mut self,
        client_public_key: PublicKey,
        peer_public_key: PublicKey,
    ) -> Result<()> {
        if let Some(counter) = self.clients.get_mut(&client_public_key) {
            counter
                .ping_counter
                .with_label_values(&[
                    &format!("{}", client_public_key),
                    &format!("{}", peer_public_key),
                ])
                .inc();
            counter
                .ping_time
                .with_label_values(&[
                    &format!("{}", client_public_key),
                    &format!("{}", peer_public_key),
                ])
                .set(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as f64);
        }
        Ok(())
    }

    pub fn inc_peer_pong_counter(
        &mut self,
        client_public_key: PublicKey,
        peer_public_key: PublicKey,
    ) -> Result<()> {
        if let Some(counter) = self.clients.get_mut(&client_public_key) {
            counter
                .pong_counter
                .with_label_values(&[
                    &format!("{}", client_public_key),
                    &format!("{}", peer_public_key),
                ])
                .inc();
            counter
                .rtt
                .with_label_values(&[
                    &format!("{}", client_public_key),
                    &format!("{}", peer_public_key),
                ])
                .set(
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as f64
                        - counter
                            .ping_time
                            .with_label_values(&[
                                &format!("{}", client_public_key),
                                &format!("{}", peer_public_key),
                            ])
                            .get(),
                );
        }
        Ok(())
    }

    pub fn print_metrics(&mut self) -> Result<()> {
        for (_, counters) in self.clients.iter() {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = counters.registry.gather();
            encoder.encode(&metric_families, &mut buffer)?;
            println!("{}", String::from_utf8(buffer)?);
        }
        Ok(())
    }

    pub fn flush_metrics_to_file(&mut self, path: String) -> Result<()> {
        if !path.is_empty() {
            let mut file = if std::path::Path::new(&path).exists() {
                fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(&path)?
            } else {
                fs::File::create(&path)?
            };

            for (_, counters) in self.clients.iter() {
                let mut buffer = vec![];
                let encoder = TextEncoder::new();
                let metric_families = counters.registry.gather();
                encoder.encode(&metric_families, &mut buffer)?;
                let _ = file.write_all(&buffer);
            }
        }
        Ok(())
    }
}
