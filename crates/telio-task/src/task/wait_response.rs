use super::Runtime;

use std::future::{pending, ready};

use async_trait::async_trait;
use futures::{future::BoxFuture, Future, FutureExt};

/// Response from [Runtime::wait].
///
/// It's recommended to use [RuntimeExt] methods.
pub struct WaitResponse<'a, E>(pub(crate) BoxFuture<'a, Result<(), E>>);

/// Typical responses from wait implementation.
#[async_trait]
pub trait RuntimeExt: Runtime {
    /// Guard multiple async operations from being interrupted by exec.
    fn guard<'a, F>(block: F) -> WaitResponse<'a, Self::Err>
    where
        F: Future<Output = Result<(), Self::Err>> + Send + 'a,
    {
        WaitResponse(block.boxed())
    }

    /// Continue to next loop iteration.
    fn next() -> WaitResponse<'static, Self::Err> {
        WaitResponse(ready(Ok(())).boxed())
    }

    /// Error out with [Runtime::Err]
    fn error(e: Self::Err) -> WaitResponse<'static, Self::Err> {
        WaitResponse(ready(Err(e)).boxed())
    }

    /// Sleep forever in loop, loop is stopped, but not deallocated.
    /// Task loop can be re-triggered using exec.
    async fn sleep_forever() -> WaitResponse<'static, Self::Err> {
        pending().await
    }
}

impl<T> RuntimeExt for T where T: Runtime {}
