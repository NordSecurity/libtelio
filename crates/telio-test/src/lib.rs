use std::net::Ipv4Addr;
use telio_crypto::SecretKey;

// This makes hanging tests easier to debug. Its immediately clear on which line the test has hung.
#[macro_export]
macro_rules! await_timeout {
    ($s:expr) => {
        tokio::select! {
          v = $s => { v }
          _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => { panic!("await took too long") }
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

// Reusing the same secret key is bad when tests are running in parallel. If there are 2 DERP
// clients with same secret key, the server will assume that they both are the same client and one
// of them will be kicked out. TODO: replace this with secret key generation (wg genkey
// equivalent)
pub const SECRET_KEY_1: SecretKey = SecretKey([0_u8; 32]);
pub const SECRET_KEY_2: SecretKey = SecretKey([1_u8; 32]);
pub const SECRET_KEY_3: SecretKey = SecretKey([2_u8; 32]);
pub const SECRET_KEY_4: SecretKey = SecretKey([3_u8; 32]);
pub const SECRET_KEY_5: SecretKey = SecretKey([4_u8; 32]);
