use std::net::UdpSocket;
use std::time::{Duration, Instant};

const PAYLOAD_SIZE: usize = 1024; // Payload size in bytes
const TEST_DURATION: Duration = Duration::new(2, 0); // Duration of the test
/// Recieve the packets
pub fn run_receiver(bind_addr: &str) {
    let socket = UdpSocket::bind(bind_addr).expect("Failed to bind receiver socket");

    let mut buffer = vec![0u8; PAYLOAD_SIZE];

    let mut total_bytes = 0;
    let start = Instant::now();

    while start.elapsed() < TEST_DURATION {
        if let Ok((len, _)) = socket.recv_from(&mut buffer) {
            total_bytes += len;
        }
    }

    let elapsed_seconds = start.elapsed().as_secs_f64();
    let throughput_mbps = (total_bytes as f64 * 8.0) / (elapsed_seconds * 1_000_000.0);

    println!(
        "Received ({} bytes) in {:.2} seconds",
        total_bytes, elapsed_seconds
    );
    println!("Throughput Rx side: {:.2} Mbps", throughput_mbps);
}
