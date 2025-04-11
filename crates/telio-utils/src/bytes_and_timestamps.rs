#[cfg(kani)]
mod kani_instant;

use std::time::Duration;

use crate::telio_log_debug;

/// Keepalive packets size
pub const KEEPALIVE_PACKET_SIZE: u64 = 32;
/// Default wireguard keepalive duration
pub const WG_KEEPALIVE: Duration = Duration::from_secs(10);

#[cfg(kani)]
type Instant = kani_instant::Instant;
#[cfg(not(kani))]
type Instant = tokio::time::Instant;

#[derive(Copy, Clone, Debug)]
/// A structure to hold the bytes and timestamps for received and transmitted data.
pub struct BytesAndTimestamps {
    /// Number of received bytes.
    pub rx_bytes: u64,
    /// Number of transmitted bytes.
    pub tx_bytes: u64,
    /// Timestamp for the last received data.
    pub rx_ts: Option<Instant>,
    /// Timestamp for the last transmitted data.
    pub tx_ts: Option<Instant>,
    /// Oldest tx_ts, greater than rx_ts
    pub first_tx_after_rx: Option<Instant>,
}

impl BytesAndTimestamps {
    /// Creates a new `BytesAndTimestamps` instance with optional initial values for received and transmitted bytes.
    pub fn new(rx_bytes: Option<u64>, tx_bytes: Option<u64>, now: Instant) -> Self {
        let rx_bytes = rx_bytes.unwrap_or_default();
        let tx_bytes = tx_bytes.unwrap_or_default();
        let first_tx_after_rx = None;
        BytesAndTimestamps {
            rx_bytes,
            tx_bytes,
            rx_ts: if rx_bytes > 0 { Some(now) } else { None },
            tx_ts: if tx_bytes > 0 { Some(now) } else { None },
            first_tx_after_rx,
        }
    }

    /// Updates the structure with new values for received and transmitted bytes.
    pub fn update(&mut self, new_rx: u64, new_tx: u64, now: Instant) {
        if new_rx > self.rx_bytes {
            self.rx_bytes = new_rx;
            self.rx_ts = Some(now);
            self.first_tx_after_rx = None;
        }

        if new_tx > self.tx_bytes {
            // Ignore the keepalive messages
            // This only works in a limited fashion because we poll every second and
            // the detection might not work as intended if there are more packets within that time window.
            // On the sender side persistent-keepalives might interfere as those are emitted regardless the activity,
            // meaning for example if persistent-keepalive is set at 5seconds then it might interfere with the
            // passive-keepalive which is a constant of 10seconds.
            if new_tx - self.tx_bytes != KEEPALIVE_PACKET_SIZE {
                self.tx_ts = Some(now);
                if let Some(rx_ts) = self.rx_ts.as_ref() {
                    if rx_ts < &now && self.first_tx_after_rx.is_none() {
                        self.first_tx_after_rx = Some(now);
                    }
                } else if self.first_tx_after_rx.is_none() {
                    self.first_tx_after_rx = Some(now);
                }
            }
            self.tx_bytes = new_tx;
        }
    }

    /// Returns the number of received bytes.
    pub fn get_rx_bytes(self) -> u64 {
        self.rx_bytes
    }

    /// Returns the number of transmitted bytes.
    pub fn get_tx_bytes(self) -> u64 {
        self.tx_bytes
    }

    /// Returns the timestamp of the last received data.
    pub fn get_rx_ts(self) -> Option<Instant> {
        self.rx_ts
    }

    /// Returns the timestamp of the last transmitted data.
    pub fn get_tx_ts(self) -> Option<Instant> {
        self.tx_ts
    }

    /// Checks if the link is up based on the round-trip time (RTT) and WireGuard keepalive interval.
    pub fn is_link_up(&self, rtt: Duration, now: Instant) -> bool {
        telio_log_debug!(
            "is_link_up. rtt={:?} rx_ts={:?} tx_ts={:?} first_tx_after_rx={:?}",
            rtt,
            self.rx_ts,
            self.tx_ts,
            self.first_tx_after_rx
        );

        if let Some(first_tx_after_rx) = self.first_tx_after_rx {
            return now.duration_since(first_tx_after_rx) < WG_KEEPALIVE + rtt;
        }

        match (self.rx_ts, self.tx_ts) {
            (Some(rx_ts), Some(tx_ts)) => tx_ts <= rx_ts,
            _ => false,
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use kani::Arbitrary;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Arbitrary)]
    enum Event {
        SleepRtt,
        SleepWgKeepalive,
        Rx,
        Tx,
        RxTx,
    }

    #[kani::proof]
    fn check() {
        const N: usize = if option_env!("CI").is_some() { 20 } else { 10 };
        let events: [Event; N] = kani::any();

        let default_sleep = Duration::from_secs(1);
        let rtt = Duration::from_secs(1);
        let mut rx = 1;
        let mut tx = 1;
        let mut current = Instant::default();
        let mut bytes_and_timestamps = BytesAndTimestamps::new(Some(rx), Some(tx), current);
        let mut time_of_last_tx = None;

        for event in events {
            match event {
                Event::SleepRtt => {
                    current += rtt;
                }
                Event::SleepWgKeepalive => {
                    current += WG_KEEPALIVE;
                }
                Event::Rx => {
                    current += default_sleep;
                    rx += 1;
                    bytes_and_timestamps.update(rx, tx, current);
                    time_of_last_tx = None;
                }
                Event::Tx => {
                    current += default_sleep;
                    tx += 1;
                    bytes_and_timestamps.update(rx, tx, current);
                    if time_of_last_tx.is_none() {
                        time_of_last_tx = Some(current);
                    }
                }
                Event::RxTx => {
                    current += default_sleep;
                    rx += 1;
                    tx += 1;
                    bytes_and_timestamps.update(rx, tx, current);
                    time_of_last_tx = None;
                }
            }
            if let Some(time_of_last_tx) = time_of_last_tx {
                if current - time_of_last_tx >= WG_KEEPALIVE + rtt {
                    assert!(!bytes_and_timestamps.is_link_up(rtt, current));
                    continue;
                }
            }
            assert!(bytes_and_timestamps.is_link_up(rtt, current));
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;

    use proptest::prelude::*;
    use proptest_derive::Arbitrary;
    use rstest::rstest;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Arbitrary)]
    enum PacketsDelta {
        Rx,
        Tx,
        RxTx,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Arbitrary)]
    enum Events {
        SleepRtt,
        SleepWgKeepalive,
        Rx,
        Tx,
        RxTx,
    }

    #[cfg(not(feature = "test-adapter"))]
    #[rstest]
    #[case(None, None, 0, false)]
    #[case(Some(0), None, 0, false)]
    #[case(None, Some(0), 0, true)]
    #[case(Some(0), Some(0), 0, true)]
    #[case(Some(0), Some(1), 0, true)]
    #[case(Some(1), Some(0), 0, true)]
    #[case(Some(0), Some(11), 0, true)]
    #[case(Some(0), Some(100), 0, true)]
    #[case(Some(0), Some(1000), 0, true)]
    #[case(Some(11), Some(0), 0, true)]
    #[case(Some(11), Some(0), 15, true)]
    #[case(Some(12), Some(11), 1, false)]
    #[case(Some(12), Some(10), 1, true)]
    fn test_bytes_and_timestamps(
        #[case] rx_sec_ago: Option<u64>,
        #[case] tx_sec_ago: Option<u64>,
        #[case] rtt: u64,
        #[case] expect_link_up: bool,
    ) {
        let rtt = Duration::from_secs(rtt);

        let max_delta = Duration::from_secs(rx_sec_ago.max(tx_sec_ago).unwrap_or_default());
        // The Instant might be a time since boot, and if this test is run right after boot
        // it can result in a overflow while subtracting few lines below.
        let start = Instant::now() + max_delta;

        let mut ops: Vec<(PacketsDelta, Instant)> = vec![];

        if let Some(rx_sec_ago) = rx_sec_ago {
            let ts = start - Duration::from_secs(rx_sec_ago);
            ops.push((PacketsDelta::Rx, ts));
        }
        if let Some(tx_sec_ago) = tx_sec_ago {
            let ts = start - Duration::from_secs(tx_sec_ago);
            ops.push((PacketsDelta::Tx, ts));
        }

        let oldest: Instant = ops.iter().map(|(_, ts)| *ts).min().unwrap_or(start);

        let mut stats = BytesAndTimestamps::new(None, None, oldest);
        let mut rx = 0;
        let mut tx = 0;

        for (kind, ts) in ops {
            match kind {
                PacketsDelta::Rx => {
                    rx += 5;
                }
                PacketsDelta::Tx => {
                    tx += 5;
                }
                PacketsDelta::RxTx => unreachable!(),
            }
            stats.update(rx, tx, ts);
        }

        assert_eq!(stats.is_link_up(rtt, start), expect_link_up);
    }

    proptest! {
        #[test]
        fn test_bytes_and_timestamps_update(mut updates: Vec<PacketsDelta>) {
            let mut rx = 0;
            let mut tx = 0;
            let mut start = Instant::now();
            let mut bytes_and_timestamps = BytesAndTimestamps::new(None, None, start);

            fn invariants(v: &BytesAndTimestamps, expect_new_first_tx: bool, expected_first_tx_value: Option<Instant>) -> Option<Instant> {
                if expect_new_first_tx {
                    assert!(v.first_tx_after_rx.is_some());
                }

                if let Some(expected_first_tx_value) = expected_first_tx_value {
                    assert_eq!(expected_first_tx_value, v.first_tx_after_rx.unwrap());
                }

                if !(expect_new_first_tx || expected_first_tx_value.is_some()) {
                    assert!(v.first_tx_after_rx.is_none(), "expected_new_first_tx: {}, value: {:?}", expect_new_first_tx, expected_first_tx_value);
                }

                match (v.first_tx_after_rx, v.rx_ts) {
                    (Some(first_tx_after_rx), Some(rx_ts)) => {
                        assert!(first_tx_after_rx > rx_ts, "bytes and timestamps: {:?}", v);
                        return Some(first_tx_after_rx)
                    }
                    (None, Some(_rx_ts)) => {},
                    (Some(first_tx_after_rx), None) => { return Some(first_tx_after_rx) },
                    _ => unreachable!()
                }

                None
            }
            let mut last_seen_first_tx = None;
            for (idx, update) in updates.iter().enumerate() {
                let mut expect_new_first_tx = false;
                let mut expected_first_tx_value = None;
                match update {
                    PacketsDelta::Rx => {
                        rx += 1;
                    }
                    PacketsDelta::Tx => {
                        tx += 1;
                        if idx > 0 {
                            if updates[idx-1] != PacketsDelta::Tx {
                                // It's a first tx byte after rx (Rx or Rx + Tx)
                                expect_new_first_tx = true;
                            } else {
                                // subsequent tx bytes should not change the first_tx_after_rx
                                expected_first_tx_value = last_seen_first_tx;
                            }
                        } else {
                             expect_new_first_tx = true;
                        }
                    }
                    PacketsDelta::RxTx => {
                        rx += 1;
                        tx += 1;
                    }
                }

                start += Duration::from_millis(1);
                bytes_and_timestamps.update(rx, tx, start);
                last_seen_first_tx = invariants(&bytes_and_timestamps, expect_new_first_tx,expected_first_tx_value);
            }
        }


        #[test]
        fn test_is_link_up(mut updates: Vec<Events> ) {
            let default_sleep = Duration::from_secs(1);
            let rtt = Duration::from_secs(1);
            let mut rx = 1;
            let mut tx = 1;
            let mut current = Instant::now();
            let mut bytes_and_timestamps = BytesAndTimestamps::new(Some(rx), Some(tx), current);
            let mut time_of_last_tx = None;

            for update in updates {
                match update {
                    Events::SleepRtt => {
                        current += rtt;

                    }
                    Events::SleepWgKeepalive => {
                        current += WG_KEEPALIVE;

                    }
                    Events::Rx => {
                        current += default_sleep;
                        rx += 1;
                        bytes_and_timestamps.update(rx, tx, current);
                        time_of_last_tx = None;
                    }
                    Events::Tx => {
                        current += default_sleep;
                        tx += 1;
                        bytes_and_timestamps.update(rx, tx, current);
                        if time_of_last_tx.is_none() {
                            time_of_last_tx = Some(current);
                        }
                    }
                    Events::RxTx => {
                        current += default_sleep;
                        rx += 1;
                        tx += 1;
                        bytes_and_timestamps.update(rx, tx, current);
                        time_of_last_tx = None;
                    }
                }
                if let Some(time_of_last_tx) = time_of_last_tx {
                    if current - time_of_last_tx >= WG_KEEPALIVE + rtt {
                        assert!(!bytes_and_timestamps.is_link_up(rtt, current));
                        continue;
                    }
                }
                assert!(bytes_and_timestamps.is_link_up(rtt, current));
            }
        }
    }
}
