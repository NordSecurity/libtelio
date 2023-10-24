use std::{any::Any, error::Error};

use async_trait::async_trait;
use futures::{
    future::{pending, BoxFuture},
    Future, FutureExt,
};
use telio_model::task_monitor::StopKind;
use telio_utils::{telio_log_error, telio_log_info, telio_log_warn};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{
    io::{
        chan::{Rx, Tx},
        Chan,
    },
    task::monitor,
    ExecError, StopResult, WaitResponse,
};

/// Runtime implementation for a [Task]'s state
#[async_trait]
pub trait Runtime: Sized {
    /// Task's name
    const NAME: &'static str;

    /// Error that may occur in [Task]
    type Err: Error + Send + 'static;

    /// Wait on state events. Called from an infinite loop
    ///
    /// Use [RuntimeExt] to create valid responses in an easier manner
    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        pending().await
    }

    /// Wait with manual control over updates
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

    /// React to stop when needed
    async fn stop(self) {}
}

/// A general runtime for compoments.
/// This task should be used in components requiring long running actions.
///
/// It takes care of:
///   * Graceful stop. (On drop or with stop)
///   * Wait entry to wait for outside triggers. (Like [Rx], sockets, timers etc)
///   * Ability to execute mutation on state without requiring mutex'es
pub struct Task<S: Runtime> {
    pub(crate) execute: Tx<Update<S, S::Err>>,
    pub(crate) stop_and_join: Option<Stopper<S>>,
}

impl<S> Task<S>
where
    S: Runtime + Send + 'static,
{
    /// Start a new task for state
    pub fn start(mut state: S) -> Self {
        let (stop, stopped) = oneshot::channel::<StopKind>();
        let Chan {
            tx: execute,
            rx: execute_rx,
        } = Chan::<Update<S, S::Err>>::default();

        let join = tokio::spawn(async move {
            let inner = async move {
                tokio::select! {
                    err = Self::run_loop(&mut state, execute_rx) => {
                        state.stop().await;
                        Err(err)
                    },
                    kind = stopped => {
                        state.stop().await;
                        // Dropping of sender assumes dropping of task.
                        Ok(kind.unwrap_or(StopKind::Dropped))
                    },
                }
            };

            // Wrap inner logic with monitoring if needed
            monitor::with_current_option(move |mon| {
                if let Some(mon) = mon {
                    mon.watch::<S>(inner).left_future()
                } else {
                    inner.right_future()
                }
            })
            .await
        });

        Self {
            execute,
            stop_and_join: Some((stop, join)),
        }
    }

    /// Execute action with exclusive access on state
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
        match self.stop_and_join.take() {
            Some((stop, join)) => {
                let stop_send_failed = stop.send(StopKind::Manual).is_err();
                let stop_result = join.await.into();
                if stop_send_failed {
                    telio_log_error!(
                        "Failed to manualy stop task: {}. Result: {:?}",
                        S::NAME,
                        &stop_result
                    );
                }
                stop_result
            }
            None => StopResult::Ok,
        }
    }

    pub(crate) async fn run_loop(state: &mut S, mut execed: Rx<Update<S, S::Err>>) -> S::Err {
        let mut watch = monitor::with_current(|m| m.loop_watch::<S>());

        loop {
            let step = state.wait_with_update(execed.recv().map(
                |e| -> BoxAction<S, Result<(), S::Err>> {
                    Box::new(move |s: &mut S| {
                        async move {
                            if let Some((action, resp)) = e {
                                let _ = resp.send(action(s).await?);
                                Ok(())
                            } else {
                                telio_log_warn!("Task's {} exec handle dropped.", S::NAME);
                                pending().await
                            }
                        }
                        .boxed()
                    })
                },
            ));

            let result = if let Some(watch) = &mut watch {
                watch.step(step).await
            } else {
                step.await
            };

            if let Err(err) = result {
                return err;
            }
        }
    }
}

impl<S: Runtime> Drop for Task<S> {
    fn drop(&mut self) {
        telio_log_info!("Task stopped - {}", S::NAME);
        if let Some((stop, _)) = self.stop_and_join.take() {
            // We can ignore error, failure would mean that inner
            // task was already closed due to other reasons
            let _ = stop.send(StopKind::Dropped);
            telio_log_warn!("Task [{}] was not stopped.", S::NAME);
        }
    }
}

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

type Stopper<S> = (
    oneshot::Sender<StopKind>,
    JoinHandle<Result<StopKind, <S as Runtime>::Err>>,
);

#[cfg(test)]
mod tests {

    use std::{
        io::{self, ErrorKind},
        time::Duration,
    };

    use crate::{task_exec, RuntimeExt};

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
        conf: Option<()>,
        thread_sleep: Option<Duration>,
    }

    impl Test {
        fn new(io: Io) -> Self {
            Self {
                task: Task::start(State {
                    io,
                    buf: Vec::new(),
                    conf: None,
                    thread_sleep: None,
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

        async fn test_configure(&self, conf: Option<()>) {
            let _ = task_exec!(&self.task, async move |s| {
                s.conf = conf;
                Ok(())
            })
            .await;
        }

        async fn test_thread_sleep(&self, sleep: Option<Duration>) {
            let _ = task_exec!(&self.task, async move |s| {
                s.thread_sleep = sleep;
                Ok(())
            })
            .await;
        }

        async fn test_fail(&self) {
            let _ = task_exec!(&self.task, async move |_s| -> Result<(), io::Error> {
                Err(io::ErrorKind::Interrupted.into())
            })
            .await;
        }

        async fn test_panic(&self) {
            let _ = task_exec!(&self.task, async move |_s| -> Result<(), io::Error> {
                panic!("inner_panic")
            })
            .await;
        }

        async fn stop(self) -> StopResult<io::Error> {
            self.task.stop().await
        }
    }

    impl State {
        async fn update(&mut self, msg: &'static str) -> Result<(), io::Error> {
            self.buf.push(msg);
            self.io
                .msg
                .tx
                .send(msg)
                .await
                .map_err(|_| io::ErrorKind::NotConnected.into())
        }
    }

    #[async_trait]
    impl Runtime for State {
        const NAME: &'static str = "Test";

        type Err = io::Error;

        async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
            if let Some(msg) = self.io.msg.rx.recv().await {
                match msg {
                    "fail" => Self::error(io::ErrorKind::ConnectionAborted.into()),
                    "sleep" => Self::sleep_forever().await,
                    msg => Self::guard(async move { self.update(msg).await }),
                }
            } else {
                Self::error(io::ErrorKind::NotConnected.into())
            }
        }

        async fn wait_with_update<F>(&mut self, update: F) -> Result<(), Self::Err>
        where
            F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
        {
            // Locks the thread, so we can test, if the Task can be dropped properly
            if let Some(sleep) = self.thread_sleep {
                std::thread::sleep(sleep);
            }

            // Runtime mimic of task's branch, which is yet to be configured
            let _config = match self.conf.as_ref() {
                Some(c) => c,
                None => {
                    return (update.await)(self).await;
                }
            };

            /*  This is the default implementation of 'Runtime::wait_with_update'
            which waits invokes wait(&mut self) function ^^^. Rust do not have a
            functionality to invoke overriden default trait methods */
            if let Some(update) = tokio::select! {
                res = self.wait() => { res.0.await?; None },
                updated = update => Some(updated),
            } {
                update(self).await?;
            }

            Ok(())
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
        test.test_configure(Some(())).await;

        rc.tx.send("ok").await.expect("Failed to send.");
        assert_eq!("ok", rc.rx.recv().await.unwrap());

        test.test_do("ok2").await;
        assert_eq!("ok2", rc.rx.recv().await.unwrap());

        assert_eq!(Some(vec!["ok", "ok2"]), test.test_get().await);

        test.stop().await;

        // Task closed on drop, and dropped on next context switch
        assert_eq!(Ok("stopped"), stopped.await);
        assert!(rc.tx.send("end").await.is_err())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_task_stops_if_dropped_without_stop() {
        /*  Task is created, locked by the `std::thread::sleep`
        and than we wait for the destructor to come into play. The
        good scenario, is that task should exit, event if it is stuck with `sleep`,
        bad case - it hangs more than `WAIT` */
        const WAIT: Duration = Duration::from_secs(1);

        let (lc, _rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        {
            let test = Test::new(Io { msg: lc, stop });
            assert_eq!(Some(vec![]), test.test_get().await);
            test.test_thread_sleep(Some(WAIT)).await;
        }

        assert_eq!(
            Ok("stopped"),
            tokio::select! {
                stop = stopped => stop,
                _ = tokio::time::sleep(WAIT * 2) => Ok("timeout"),
            }
        );
    }

    #[tokio::test]
    async fn test_task_stopped_on_failure_in_exec() {
        let (lc, rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });
        test.test_configure(Some(())).await;

        test.test_fail().await;

        assert_eq!(Ok("stopped"), stopped.await);

        assert!(rc.tx.send("end").await.is_err());

        assert_eq!(
            ErrorKind::Interrupted,
            test.stop().await.resume_unwind().unwrap_err().kind()
        );
    }

    #[tokio::test]
    async fn test_task_stopped_on_failure_in_wait() {
        let (lc, rc) = Chan::pipe();
        let (stop, stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });
        test.test_configure(Some(())).await;

        rc.tx.send("fail").await.expect("failed to send");

        assert_eq!(Ok("stopped"), stopped.await);

        assert!(rc.tx.send("end").await.is_err());

        assert_eq!(
            ErrorKind::ConnectionAborted,
            test.stop().await.resume_unwind().unwrap_err().kind()
        );
    }

    #[tokio::test]
    #[should_panic]
    async fn test_task_captures_panic() {
        let (lc, _rc) = Chan::pipe();
        let (stop, _stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });
        test.test_configure(Some(())).await;

        test.test_panic().await;

        let _ = test.stop().await.resume_unwind();
    }

    #[tokio::test]
    async fn test_sleep_cancellation() {
        let (lc, mut rc) = Chan::pipe();
        let (stop, _stopped) = oneshot::channel();
        let test = Test::new(Io { msg: lc, stop });
        test.test_configure(Some(())).await;

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

        assert!(test.stop().await.resume_unwind().is_ok());
    }
}
