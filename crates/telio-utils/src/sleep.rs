use futures::Future;
use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{sleep, Duration, Sleep};

/// Wrapper for Sleep to be pinned and return a value on completion

pub struct PinnedSleep<T: Copy>(Pin<Box<Sleep>>, Pin<Box<T>>);

impl<T> fmt::Debug for PinnedSleep<T>
where
    T: fmt::Debug + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PinnedSleep")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

impl<T: Copy> PinnedSleep<T> {
    /// PinnedSleep constructor
    pub fn new(duration: Duration, ret: T) -> Self {
        Self(Box::pin(sleep(duration)), Box::pin(ret))
    }
}

impl<T: Copy> Future for PinnedSleep<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.as_mut().poll(cx) {
            Poll::Ready(_) => Poll::Ready(*self.1),
            Poll::Pending => Poll::Pending,
        }
    }
}
