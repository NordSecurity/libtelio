use std::collections::HashMap;

const MONITORING_INTERVAL_MILLIS: u64 = 3000;

pub struct Metrics {
    /// clients - connected client count; should be even number if no errors
    ///           as clients are added in pairs
    pub clients: usize,
    /// rtts - vector packet RTTs; tuple (Timestamp-in-ms, RTT-in-ms, DERP-name)
    ///        keeps only received in the last MONITORING_INTERVAL_MILLIS
    pub rtts: Vec<(u64, u16, String)>,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            clients: 0,
            rtts: Vec::new(),
        }
    }

    pub fn inc_clients(&mut self) {
        self.clients += 1;
    }

    pub fn get_clients(&mut self) -> usize {
        self.clients
    }

    pub fn add_rtt(&mut self, now: u64, rtt: u16, derp1: String) {
        self.remove_outdated_rtt(now);

        if let Some((last_time_received, _, _)) = self.rtts.last() {
            if *last_time_received > now {
                println!("WARNING: Time went back, ignoring RTT...");
                return;
            }
        }

        self.rtts.push((now, rtt, derp1));
    }

    pub fn print_rtts(&mut self) {
        if self.rtts.is_empty() {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.remove_outdated_rtt(now);

        let mut rtt_sum_per_derp = HashMap::new();
        let mut packets_per_derp = HashMap::new();

        for (_t, rtt, derp1) in &self.rtts {
            rtt_sum_per_derp
                .entry(derp1)
                .and_modify(|sum| *sum += *rtt as u64)
                .or_insert(*rtt as u64);
            packets_per_derp
                .entry(derp1)
                .and_modify(|sum| *sum += 1)
                .or_insert(1);
        }
        for (derp1, packet_count) in &packets_per_derp {
            let rtt_sum = if let Some(rtt) = rtt_sum_per_derp.get(derp1) {
                *rtt
            } else {
                panic!("Err! - Invalid rtt");
            };
            let rtt_avg = rtt_sum as f64 / *packet_count as f64;
            println!("* Avg. RTT via [{}]: {:.2} ms", derp1, rtt_avg);
        }
    }

    fn remove_outdated_rtt(&mut self, now: u64) {
        let tooold = now - MONITORING_INTERVAL_MILLIS;
        let index = self.rtts.iter().position(|(t, _rtt, _derp1)| *t > tooold);
        match index {
            Some(i) => {
                self.rtts = if let Some(rtts) = self.rtts.get(i..) {
                    rtts
                } else {
                    println!("Err! No rtts found. Invalid index");
                    return;
                }
                .into()
            }
            None => self.rtts.clear(),
        }
    }
}
