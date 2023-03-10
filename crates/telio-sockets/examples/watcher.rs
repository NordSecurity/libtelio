#[cfg(windows)]
mod platform {
    use std::{thread, time};
    use telio_sockets::protector::platform::IfWatcher;
    use tokio::sync::mpsc::channel;
    pub fn foo() {
        println!("Starting watcher...");
        let (tx, mut rx) = channel(100);
        let _watcher = IfWatcher::new(tx);
        loop {
            println!("Loop started...");
            let interface = rx.blocking_recv().unwrap();
            println!(
                "interface index {:?}, ip {:?}",
                interface.index, interface.ip
            );
            let ten_millis = time::Duration::from_millis(10);
            thread::sleep(ten_millis);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn foo() {}
}

fn main() {
    platform::foo();
}
