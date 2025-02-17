use std::net::Ipv4Addr;

// This makes hanging tests easier to debug. Its immediately clear on which line the test has hung.
#[macro_export]
macro_rules! await_timeout {
    ($s:expr) => {
        tokio::select! {
          v = $s => { v }
          _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => { panic!("await took too long") }
        }
    };
}

/// Calculates elapsed time with defined rounding
#[macro_export]
macro_rules! assert_elapsed {
    ($start:expr, $dur:expr, $round:expr) => {{
        let elapsed = $start.elapsed();
        let lower: std::time::Duration = $dur;
        let round: std::time::Duration = $round;

        assert!(
            elapsed >= lower - round && elapsed <= lower + round,
            "actual = {:?}, expected = {:?}",
            elapsed,
            lower,
        );
    }};
}

pub const DERP_HOST: &str = "https://de1047.nordvpn.com:8765";
pub const DERP_IPV4: Ipv4Addr = Ipv4Addr::new(185, 196, 22, 215);
pub const DERP_PUBLIC_KEY: &str = "SPB77H13eXlOdWc+PGrX6oAQfCvz2me1fvAB0lrxN0Y=";
