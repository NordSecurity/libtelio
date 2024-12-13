use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};

const PAYLOAD_SIZE: usize = 1024; // Payload size in bytes
const TEST_DURATION: Duration = Duration::new(2, 0); // Duration of the test
/// Send the packets
pub fn run_sender(target: &str) {
    let socket = UdpSocket::bind("127.0.0.1:1234").expect("Failed to bind sender socket");

    let sock_addr = SocketAddr::from_str(target).unwrap();
    // SocketAddr::from(([127, 0, 0, 1], config.wg_port));

    let payload = vec![0u8; PAYLOAD_SIZE];
    let start = Instant::now();
    let mut total_bytes = 0;

    while start.elapsed() < TEST_DURATION {
        match socket.send_to(&payload, sock_addr) {
            Ok(len) => total_bytes += len,
            Err(e) => (),
        }
    }

    let elapsed_seconds = start.elapsed().as_secs_f64();
    let throughput_mbps = (total_bytes as f64 * 8.0) / (elapsed_seconds * 1_000_000.0);

    println!(
        "Sent packets {} bytes in {:.2} seconds",
        total_bytes, elapsed_seconds
    );
    println!("Throughput: {:.2} Mbps", throughput_mbps);
}

#[cfg(test)]
mod tests {
    use crate::server::run_receiver;

    use super::*;
    use std::thread;

    #[test]
    fn test_throughput() {
        let receiver_thread = thread::spawn(|| {
            run_receiver("127.0.0.1:12345");
        });

        thread::sleep(Duration::from_secs(1)); // Allow receiver to start

        let sender_thread = thread::spawn(|| {
            run_sender("127.0.0.1:12345");
        });

        sender_thread.join().expect("Sender thread panicked");
        receiver_thread.join().expect("Receiver thread panicked");
    }
}
