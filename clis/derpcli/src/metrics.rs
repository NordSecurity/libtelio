#![allow(unwrap_check)]
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

    pub fn add_client(&mut self, client_public_key: PublicKey) {
        let counters = Counters {
            ping_counter: CounterVec::new(
                Opts::new(
                    "ping_counter",
                    format!("client {} ping_counter", client_public_key,),
                ),
                &["client", "peer"],
            )
            .unwrap(),
            pong_counter: CounterVec::new(
                Opts::new(
                    "pong_counter",
                    format!("client {} pong_counter", client_public_key,),
                ),
                &["client", "peer"],
            )
            .unwrap(),
            rtt: GaugeVec::new(
                Opts::new(
                    "rtt",
                    format!(
                        "client {} last ping pong round trip time (ms)",
                        client_public_key,
                    ),
                ),
                &["client", "peer"],
            )
            .unwrap(),
            ping_time: GaugeVec::new(
                Opts::new(
                    "ping_time",
                    format!("client {} ping time (ms)", client_public_key,),
                ),
                &["client", "peer"],
            )
            .unwrap(),
            registry: Registry::new(),
        };

        counters
            .registry
            .register(Box::new(counters.ping_counter.clone()))
            .unwrap();
        counters
            .registry
            .register(Box::new(counters.pong_counter.clone()))
            .unwrap();
        counters
            .registry
            .register(Box::new(counters.rtt.clone()))
            .unwrap();
        counters
            .registry
            .register(Box::new(counters.ping_time.clone()))
            .unwrap();

        self.clients.insert(client_public_key, counters);
    }

    pub fn inc_peer_ping_counter(
        &mut self,
        client_public_key: PublicKey,
        peer_public_key: PublicKey,
    ) {
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
                .set(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as f64,
                );
        }
    }

    pub fn inc_peer_pong_counter(
        &mut self,
        client_public_key: PublicKey,
        peer_public_key: PublicKey,
    ) {
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
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as f64
                        - counter
                            .ping_time
                            .with_label_values(&[
                                &format!("{}", client_public_key),
                                &format!("{}", peer_public_key),
                            ])
                            .get(),
                );
        }
    }

    pub fn print_metrics(&mut self) {
        for (_, counters) in self.clients.iter() {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = counters.registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            println!("{}", String::from_utf8(buffer).unwrap());
        }
    }

    pub fn flush_metrics_to_file(&mut self, path: String) {
        if path != "" {
            let mut file = if std::path::Path::new(&path).exists() {
                fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(&path)
                    .unwrap()
            } else {
                fs::File::create(&path).unwrap()
            };

            for (_, counters) in self.clients.iter() {
                let mut buffer = vec![];
                let encoder = TextEncoder::new();
                let metric_families = counters.registry.gather();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                let _ = file.write_all(&buffer);
            }
        }
    }
}
