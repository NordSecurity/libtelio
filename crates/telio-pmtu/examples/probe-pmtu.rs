use std::net::ToSocketAddrs;

use tracing_subscriber::filter::LevelFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .without_time()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let Some(addr) = std::env::args().nth(1) else {
        println!("Missing destination address. Usage: probe-pmtu <dst addr>");
        std::process::exit(1);
    };

    let ipaddr = match (addr.as_str(), 0).to_socket_addrs() {
        Ok(mut vec) => {
            if let Some(ipaddr) = vec.next() {
                ipaddr.ip()
            } else {
                println!("Failed to resolve address {addr}. No candidates");
                std::process::exit(1);
            }
        }
        Err(err) => {
            println!("Failed to resolve address {addr}. Reason:\n{err:#?}");
            std::process::exit(1);
        }
    };

    let sock = match telio_pmtu::PMTUSocket::new(ipaddr) {
        Ok(sock) => sock,
        Err(err) => {
            println!("Failed to create socket. Reason:\n{err:#?}");
            std::process::exit(1);
        }
    };

    match sock.probe_pmtu().await {
        Ok(pmtu) => println!("Discovered PMTU: {pmtu}"),
        Err(err) => {
            println!("Failed to probe PMTU. Reason:\n{err:#?}");
            std::process::exit(1);
        }
    }
}
