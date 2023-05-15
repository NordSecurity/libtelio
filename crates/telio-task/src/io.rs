//! Types for basic io comuncation between tasks

use futures::Future;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, OwnedPermit};

/// Error type for Chan
pub type ChanSendError<T> = mpsc::error::SendError<T>;

/// Send error type for McChan
pub type McChanSendError<T> = broadcast::error::SendError<T>;

/// Receive error type for McChan
pub type McChanRcvError = broadcast::error::RecvError;

/// Default size to be used as backing buffer for queues.
pub const DEFAULT_BUFFER_SIZE: usize = 4096;

/// Types for multi producer, single consumer channels
pub mod chan {
    /// Default sender channel
    pub type Tx<T> = tokio::sync::mpsc::Sender<T>;

    /// Default reciever channel
    pub type Rx<T> = tokio::sync::mpsc::Receiver<T>;
}

/// Channel encapsulating multi producer, single consumer send and reciever sides
pub struct Chan<T> {
    /// Recieve half.
    pub rx: chan::Rx<T>,
    /// Send half.
    pub tx: chan::Tx<T>,
}

impl<T: Send> Chan<T> {
    /// Create a channel pointing to it self of requested size.
    pub fn new(buffer: usize) -> Self {
        let (tx, rx) = mpsc::channel::<T>(buffer);
        Self { tx, rx }
    }

    /// Create two channels piped to each other, with specified buffer size.
    pub fn pipe_with_size(buffer: usize) -> (Self, Self) {
        let (ltx, rrx) = mpsc::channel::<T>(buffer);
        let (rtx, lrx) = mpsc::channel::<T>(buffer);

        (Self { tx: ltx, rx: lrx }, Self { tx: rtx, rx: rrx })
    }

    /// Create two channels piped to each other, with default buffer size.
    pub fn pipe() -> (Self, Self) {
        Self::pipe_with_size(DEFAULT_BUFFER_SIZE)
    }
}

impl<T: Send> Default for Chan<T> {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE)
    }
}

/// Types for multi producer, multi consumer channels
pub mod mc_chan {
    /// Default sender channel
    pub type Tx<T> = tokio::sync::broadcast::Sender<T>;
    /// Default reciever channel
    pub type Rx<T> = tokio::sync::broadcast::Receiver<T>;
}

/// Channel encapsulating multi producer, multi consumer send and reciever sides
pub struct McChan<T> {
    /// Recieve half
    pub rx: mc_chan::Rx<T>,
    /// Send half
    pub tx: mc_chan::Tx<T>,
}

impl<T: Clone> McChan<T> {
    /// Create a channel pointing to it self of requested size.
    pub fn new(buffer: usize) -> Self {
        let (tx, rx) = broadcast::channel::<T>(buffer);
        Self { tx, rx }
    }

    /// Create two channels piped to each other, with specified buffer size.
    pub fn pipe_with_size(buffer: usize) -> (Self, Self) {
        let (ltx, rrx) = broadcast::channel::<T>(buffer);
        let (rtx, lrx) = broadcast::channel::<T>(buffer);

        (Self { tx: ltx, rx: lrx }, Self { tx: rtx, rx: rrx })
    }

    /// Create two channels piped to each other, with default buffer size.
    pub fn pipe() -> (Self, Self) {
        Self::pipe_with_size(DEFAULT_BUFFER_SIZE)
    }
}

/// Wait for chan::Tx to be ready, and only then await wanted future
pub async fn wait_for_tx<T: Send, F, O>(tx: &chan::Tx<T>, fut: F) -> Option<(OwnedPermit<T>, O)>
where
    F: Future<Output = O>,
{
    let permit = tx.clone().reserve_owned().await.ok()?;
    Some((permit, fut.await))
}

impl<T: Clone> Default for McChan<T> {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    use super::*;

    const SPEED: Duration = Duration::from_nanos(100);
    const TICKS: usize = 100;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_deadlock_pattern() {
        async fn forward(mut ch: Chan<Vec<u8>>, msg: Vec<u8>, expect: Vec<u8>) {
            let mut rx_tick = 0;
            let mut tx_tick = 0;

            while tx_tick < TICKS && rx_tick < TICKS {
                tokio::select! {
                    // Simulate outisde tx A <- <Self> <- B
                    Some(data) = delay(ch.rx.recv()), if rx_tick <= TICKS => {
                        rx_tick += 1;
                        println!("{} <-- {}: {}", msg[0], expect[0], rx_tick);
                        assert_eq!(data, expect);
                    },
                    // Simulate outside rx A -> <Self> -> B
                    _ = sleep(SPEED), if tx_tick <= TICKS => {
                        tx_tick += 1;
                        println!("{} --> {}: {}", msg[0], expect[0], tx_tick);
                        let _ = ch.tx.send(msg.clone()).await;
                    }
                    else => { break }
                }
            }
        }
        let (rc, lc) = Chan::pipe_with_size(1);
        let right = tokio::spawn(forward(rc, vec![1u8; 1480], vec![2u8; 1480]));
        let left = tokio::spawn(forward(lc, vec![2u8; 1480], vec![1u8; 1480]));

        timeout(Duration::from_secs(3), async move {
            let _ = right.await;
            let _ = left.await;
        })
        .await
        .expect_err("Should have deadlocked!!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_safe_pattern() {
        async fn forward(mut ch: Chan<Vec<u8>>, msg: Vec<u8>, expect: Vec<u8>) {
            let mut rx_tick = 0;
            let mut tx_tick = 0;
            let mut my_permit = None;

            while tx_tick < TICKS || rx_tick < TICKS {
                tokio::select! {
                    // Simulate outisde tx A <- <Self> <- B
                    Some(data) = delay(ch.rx.recv()) => {
                        rx_tick += 1;
                        println!("{} <-- {}: {}", msg[0], expect[0], rx_tick);
                        assert_eq!(data, expect);
                    }
                    // Enforce back presure
                    Ok(permit) = ch.tx.reserve(), if my_permit.is_none() => {
                        tx_tick += 1;
                        println!("{} -x- {}: {}", msg[0], expect[0], tx_tick);
                        my_permit.replace(permit);
                    }
                    // Simulate outisde rx A -> <Self> -> B
                    _ = sleep(SPEED), if my_permit.is_some() => {
                        let permit = my_permit.take().expect("Was checked aready to be some.");
                        println!("{} --> {}: {}", msg[0], expect[0], tx_tick);
                        let _ = permit.send(msg.clone());
                    }
                    else => { break }
                }
            }
        }

        let (rc, lc) = Chan::pipe_with_size(1);
        let right = tokio::spawn(forward(rc, vec![1u8; 1480], vec![2u8; 1480]));
        let left = tokio::spawn(forward(lc, vec![2u8; 1480], vec![1u8; 1480]));

        timeout(Duration::from_secs(10), async move {
            let _ = right.await;
            let _ = left.await;
        })
        .await
        .expect("Should have not deadlocked!!");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wait_for_tx() {
        async fn forward(mut ch: Chan<Vec<u8>>, msg: Vec<u8>, expect: Vec<u8>) {
            let mut rx_tick = 0;
            let mut tx_tick = 0;

            while tx_tick < TICKS && rx_tick < TICKS {
                tokio::select! {
                    // Simulate outisde tx A <- <Self> <- B
                    Some(data) = delay(ch.rx.recv()), if rx_tick <= TICKS => {
                        rx_tick += 1;
                        println!("{} <-- {}: {}", msg[0], expect[0], rx_tick);
                        assert_eq!(data, expect);
                    },
                    // Simulate outside rx A -> <Self> -> B
                    Some((permit, _)) = wait_for_tx(&ch.tx, sleep(SPEED)), if tx_tick <= TICKS => {
                        tx_tick += 1;
                        println!("{} --> {}: {}", msg[0], expect[0], tx_tick);
                        let _ = permit.send(msg.clone());
                    }
                    else => { break }
                }
            }
        }

        let (rc, lc) = Chan::pipe_with_size(1);
        let right = tokio::spawn(forward(rc, vec![1u8; 1480], vec![2u8; 1480]));
        let left = tokio::spawn(forward(lc, vec![2u8; 1480], vec![1u8; 1480]));

        timeout(Duration::from_secs(10), async move {
            let _ = right.await;
            let _ = left.await;
        })
        .await
        .expect("Should have not deadlocked!!");
    }

    async fn delay<T>(fut: impl std::future::Future<Output = T>) -> T {
        sleep(SPEED * 3).await;
        fut.await
    }
}
