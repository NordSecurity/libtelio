use std::{any::Any, sync::Arc};

use async_trait::async_trait;
use futures::{
    future::{pending, ready, BoxFuture},
    Future, FutureExt,
};
use tokio::{
    sync::{oneshot, Notify},
    task::JoinHandle,
};

use telio_utils::telio_log_warn;

use crate::io::{
    chan::{Rx, Tx},
    Chan,
};

/// Runtime implementation for a [Task]'s state
#[async_trait]
pub trait Runtime: Sized {
    /// Task's name
    const NAME: &'static str;

    /// Error that may occur in [Task]
    type Err: Send + 'static;

    /// Wait on state events. Called from an infinite loop.
    ///
    /// Use [RuntimeExt] to create valid responses in an easier manner.
    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        WaitResponse(pending().boxed())
    }

    /// Wait with manual controll over updates
    async fn wait_with_update<F>(&mut self, updated: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        if let Some(update) = tokio::select! {
            res = self.wait() => { res.0.await?; None },
            update = updated => Some(update),
        } {
            update(self).await?;
        }
        Ok(())
    }

    /// React to stop when needed.
    async fn stop(self) {}
}

/// Typical responses from wait implementation.
#[async_trait]
pub trait RuntimeExt: Runtime {
    /// Guard multiple async operations form being interupted by exec.
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

    /// Sleep forever in loop, loop is stopped, but not dealocated.
    /// Task loop can be retrigger using exec.
    async fn sleep_forever() -> WaitResponse<'static, Self::Err> {
        pending().await
    }
}

impl<T> RuntimeExt for T where T: Runtime {}

/// A general runtime for compoments.
///
/// This task should be used in components requiring long running actions.
///
/// It takes care of:
///   * Gracefull stop. (On drop or with stop)
///   * Wait entry to wait for outside trigers. (Like [Rx], sockets, timers etc)
///   * Ability to execute mutation on state without requiring mutex'es
pub struct Task<S: Runtime> {
    stop: Arc<Notify>,
    execute: Tx<Update<S, S::Err>>,
    join: Option<JoinHandle<Result<(), S::Err>>>,
}

/// Task was stopped durring execution.
#[derive(Debug, thiserror::Error)]
#[error("Failed to execute.")]
pub struct ExecError;

/// Task stop status.
#[derive(Debug)]
pub enum StopResult<E> {
    /// Task was stopped succesfully
    Ok,
    /// Task stopped due to internal error.
    Err(E),
    /// Task panic'ed
    Panic(Box<dyn Any + Send + 'static>),
}

/// Response from [Runtime::wait].
///
/// It's recommended to use [RuntimeExt] methods.
pub struct WaitResponse<'a, E>(BoxFuture<'a, Result<(), E>>);

/// Future closure
pub trait Action<V, R = ()>
where
    for<'a> Self: FnOnce(&'a mut V) -> BoxFuture<'a, R> + Send + 'static,
    R: Send + 'static,
{
}

impl<T, V, R> Action<V, R> for T
where
    for<'a> T: FnOnce(&'a mut V) -> BoxFuture<'a, R> + Send + 'static,
    R: Send + 'static,
{
}

/// Boxed future closure
pub type BoxAction<V, R = ()> = Box<dyn Action<V, R>>;

type AnySend = Box<dyn Any + Send + 'static>;

type Resp<T> = oneshot::Sender<T>;

type Update<S, E> = (BoxAction<S, Result<AnySend, E>>, Resp<AnySend>);

impl<S> Task<S>
where
    S: Runtime + Send + 'static,
{
    /// Start a new task for state.
    pub fn start(mut state: S) -> Self {
        let stop = Arc::new(Notify::new());
        let Chan {
            tx: execute,
            rx: execute_rx,
        } = Chan::<Update<S, S::Err>>::default();

        let stopped = stop.clone();
        let join = Some(tokio::spawn(async move {
            tokio::select! {
                res = Self::run_loop(&mut state, execute_rx) => {
                    state.stop().await;
                    res
                },
                _ = stopped.notified() => {
                    state.stop().await;
                    Ok(())
                },
            }
        }));

        println!("task started - {}", S::NAME);

        Self {
            stop,
            execute,
            join,
        }
    }

    /// Execute action with exlusive access on state.
    #[allow(mpsc_blocking_send)]
    pub async fn exec<A, V>(&self, action: A) -> Result<V, ExecError>
    where
        for<'a> A: FnOnce(&'a mut S) -> BoxFuture<'a, Result<V, S::Err>> + Send + 'static,
        V: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let act: BoxAction<S, Result<AnySend, S::Err>> =
            Box::new(|s: &mut S| action(s).map(|r| r.map(|v| Box::new(v) as AnySend)).boxed());

        if self.execute.send((act, tx)).await.is_err() {
            Err(ExecError)
        } else if let Ok(res) = rx.await {
            match res.downcast::<V>() {
                Ok(r) => Ok(*r),
                Err(_) => Err(ExecError),
            }
        } else {
            Err(ExecError)
        }
    }

    /// Stop task
    pub async fn stop(mut self) -> StopResult<S::Err> {
        println!("task stopped - {}", S::NAME);
        self.stop.notify_one();
        let join = match self.join.take() {
            Some(v) => v,
            None => return StopResult::Ok,
        };

        match join.await {
            Ok(Ok(())) => StopResult::Ok,
            Ok(Err(e)) => StopResult::Err(e),
            Err(e) if e.is_panic() => StopResult::Panic(e.into_panic()),
            _ => StopResult::Ok,
        }
    }

    async fn run_loop(state: &mut S, mut execed: Rx<Update<S, S::Err>>) -> Result<(), S::Err> {
        loop {
            state
                .wait_with_update(execed.recv().map(|e| -> BoxAction<S, Result<(), S::Err>> {
                    Box::new(move |s: &mut S| {
                        async move {
                            if let Some((action, resp)) = e {
                                let _ = resp.send(action(s).await?);
                            }
                            Ok(())
                        }
                        .boxed()
                    })
                }))
                .await?;
        }
    }
}

impl<S: Runtime> Drop for Task<S> {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.stop.notify_waiters();
            telio_log_warn!("Task [{}] was not stopped.", S::NAME);
        }
    }
}

impl<E> StopResult<E> {
    /// Stopped successfully
    pub fn is_ok(&self) -> bool {
        matches!(self, &StopResult::Ok)
    }

    /// Stopped due to internal error
    pub fn is_err(&self) -> bool {
        matches!(self, &StopResult::Err(_))
    }

    /// Stopped due to inner panic
    pub fn is_panic(&self) -> bool {
        matches!(self, &StopResult::Panic(_))
    }

    /// Return Ok for propper stop or Err if internal error occured.
    ///
    /// # Panics
    /// Propogets panic if task stopped due to panic
    pub fn resume_unwind(self) -> Result<(), E> {
        match self {
            Self::Ok => Ok(()),
            Self::Err(e) => Err(e),
            Self::Panic(p) => std::panic::resume_unwind(p),
        }
    }
}

impl<E: PartialEq> PartialEq for StopResult<E> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (&Self::Ok, &Self::Ok) => true,
            (&Self::Err(el), &Self::Err(er)) => el == er,
            (&Self::Panic(_), &Self::Panic(_)) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use crate::task_exec;

    use super::*;
    use async_trait::async_trait;
    use tokio::time::timeout;

    struct Test {
        task: Task<State>,
    }

    struct Io {
        msg: Chan<&'static str>,
        stop: oneshot::Sender<&'static str>,
    }

    struct State {
        io: Io,
        buf: Vec<&'static str>,
    }

    impl Test {
        fn new(io: Io) -> Self {
            Self {
                task: Task::start(State {
                    io,
                    buf: Vec::new(),
                }),
            }
        }

        async fn test_do(&self, name: &'static str) {
            let _ = task_exec!(&self.task, async move |state| state.update(name).await).await;
        }

        async fn test_get(&self) -> Option<Vec<&'static str>> {
            task_exec!(&self.task, async move |state| Ok(state.buf.clone()))
                .await
                .ok()
        }

        async fn test_fail(&self) {
            let _ = task_exec!(&self.task, async move |_s| -> Result<(), ()> { Err(()) }).await;
        }

        async fn test_panic(&self) {
            let _ = task_exec!(&self.task, async move |_s| -> Result<(), ()> {
                panic!("inner_pannic")
            })
            .await;
        }

        async fn stop(self) -> StopResult<()> {
            self.task.stop().await
        }
    }

    impl State {
        async fn update(&mut self, msg: &'static str) -> Result<(), ()> {
            self.buf.push(msg);
            self.io.msg.tx.send(msg).await.map_err(|_| ())
        }
    }

    #[async_trait]
    impl Runtime for State {
        const NAME: &'static str = "Test";

        type Err = ();

        async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
            if let Some(msg) = self.io.msg.rx.recv().await {
                match msg {
                    "fail" => Self::error(()),
                    "sleep" => Self::sleep_forever().await,
                    msg => Self::guard(async move { self.update(msg).await }),
                }
            } else {
                Self::error(())
            }
        }

        async fn stop(self) {
            let _ = self.io.stop.send("stopped");
        }
    }

    #[tokio::test]
    async fn test_task_default_behaviour() {
        let (lc, mut rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });

        rc.tx.send("ok").await.expect("Failed to send.");
        assert_eq!("ok", rc.rx.recv().await.unwrap());

        test.test_do("ok2").await;
        assert_eq!("ok2", rc.rx.recv().await.unwrap());

        assert_eq!(Some(vec!["ok", "ok2"]), test.test_get().await);

        test.stop().await;

        // Task closed on drop, and droped on next context switch.
        assert_eq!(Ok("stopped"), stopped.await);
        assert!(rc.tx.send("end").await.is_err())
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic]
    #[ignore = "panic removed from `Drop`"]
    async fn test_task_panics_if_droped_without_stop() {
        let (lc, _rc) = Chan::pipe();
        let (stop, _stopped) = oneshot::channel();
        {
            let test = Test::new(Io { msg: lc, stop });
            assert_eq!(Some(vec![]), test.test_get().await);
        }
    }

    #[cfg(not(debug_assertions))]
    #[tokio::test]
    async fn test_task_stops_if_droped_without_stop() {
        let (lc, _rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        {
            let test = Test::new(Io { msg: lc, stop });
            assert_eq!(Some(vec![]), test.test_get().await);
        }
        assert_eq!(Ok("stopped"), stopped.await);
    }

    #[tokio::test]
    async fn test_task_stopped_on_failure_in_exec() {
        let (lc, rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });

        test.test_fail().await;

        assert_eq!(Ok("stopped"), stopped.await);

        assert!(rc.tx.send("end").await.is_err());

        assert_eq!(Err(()), test.stop().await.resume_unwind());
    }

    #[tokio::test]
    async fn test_task_stopped_on_failure_in_wait() {
        let (lc, rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });

        rc.tx.send("fail").await.expect("failed to send");

        assert_eq!(Ok("stopped"), stopped.await);

        assert!(rc.tx.send("end").await.is_err());

        assert_eq!(Err(()), test.stop().await.resume_unwind());
    }

    #[tokio::test]
    #[should_panic]
    async fn test_task_captures_panic() {
        let (lc, _rc) = Chan::pipe();
        let (stop, _stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });

        test.test_panic().await;

        let _ = test.stop().await.resume_unwind();
    }

    #[tokio::test]
    async fn test_sleep_cancelation() {
        let (lc, mut rc) = Chan::pipe();
        let (stop, _stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });

        rc.tx.send("sleep").await.expect("failed to send sleep");

        rc.tx.send("ok").await.expect("Failed to send.");
        // Timeout due to sleep
        assert!(matches!(
            timeout(Duration::from_millis(500), rc.rx.recv()).await,
            Err(_)
        ));

        // Resume work after update
        test.test_do("ok2").await;
        assert_eq!("ok2", rc.rx.recv().await.unwrap());
        assert_eq!("ok", rc.rx.recv().await.unwrap());

        assert_eq!(Ok(()), test.stop().await.resume_unwind());
    }
}
