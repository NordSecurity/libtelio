use std::{
    cell::RefCell,
    collections::HashMap,
    panic,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::{future::poll_fn, Future};

use telio_model::{
    api_config::FeatureTaskMonitor as MonitorConfig,
    task_monitor::{MonitorEvent, StopKind, StopReason},
};
use telio_utils::{runtime::Builder, task, telio_log_warn};

use crate::Runtime;

type TaskMonitorHandler = Arc<dyn Fn(MonitorEvent) + Send + Sync + 'static>;

/// Telio Task Monitor
///
/// Allowes monitoring of exits and other failues of all task created using [task::Runtime]
#[derive(Clone)]
pub struct TaskMonitor {
    config: MonitorConfig,
    handler: TaskMonitorHandler,
}

impl TaskMonitor {
    /// Create a new task monitor
    pub fn new<H>(config: MonitorConfig, handler: H) -> Self
    where
        H: Fn(MonitorEvent) + Send + Sync + 'static,
    {
        let event_limiter: Mutex<HashMap<MonitorEvent, Instant>> = Mutex::new(HashMap::new());
        let debounce_time = Duration::from_millis(
            config
                .duration_between_reporting_same_event_ms
                .unwrap_or(MonitorConfig::DEFAULT_DURATION_BETWEEN_REPORTING_SAME_EVENT),
        );
        Self {
            config,
            handler: Arc::new(move |event| {
                if let Ok(mut el) = event_limiter.lock() {
                    let now = Instant::now();
                    let can_send = el
                        .get(&event)
                        .map(|last| now.duration_since(*last) > debounce_time)
                        .unwrap_or(true);

                    if can_send {
                        el.insert(event.clone(), now);
                        (handler)(event)
                    }
                }
            }),
        }
    }

    /// Setup task monitor for tokio thread pool
    pub fn on_thread_start(&self) {
        CURRENT_MONITOR.with(|m| *m.borrow_mut() = Some(self.clone()))
    }

    /// Cleanup task monitor for tokio thread pool
    pub fn on_thread_stop(&self) {
        CURRENT_MONITOR.with(|m| *m.borrow_mut() = None)
    }

    pub(crate) fn report(&self, event: MonitorEvent) {
        (self.handler)(event)
    }

    /// This must be called from within a tokio task
    pub(crate) fn watch<R: Runtime>(
        &self,
        inner: impl Future<Output = Result<StopKind, R::Err>> + Send + 'static,
    ) -> impl Future<Output = Result<StopKind, R::Err>> + Send + 'static {
        let handler = self.handler.clone();
        async move {
            (handler)(MonitorEvent::TaskStart { name: R::NAME });

            // This is the simplest way to capture panic.
            // It should be possible to do this with catch_unwind,
            // but it is way too complex to implement for a functionality that
            // is primarily used for debugging.
            let res = tokio::spawn(inner).await;

            let reason: StopReason = { &res }.into();

            (handler)(MonitorEvent::TaskStop {
                name: R::NAME,
                reason,
            });

            // This future is also run as a task, so we need to propogate inner result
            match res {
                Ok(res) => res,
                Err(err) if err.is_cancelled() => {
                    // This should not be really reachable as there are no cancel calls
                    // to inner task
                    telio_log_warn!("Task {} was cancelled", R::NAME);
                    Ok(StopKind::Dropped)
                }
                Err(err) => panic::resume_unwind(err.into_panic()),
            }
        }
    }

    /// Create task wait loop watcher
    pub(crate) fn loop_watch<R: Runtime>(&self) -> LoopWatcher {
        LoopWatcher {
            task_name: R::NAME,
            monitor: self.clone(),
            immediate_poll_count: 0,
        }
    }
}

pub trait TokioBuilderExt {
    /// Setup task monitor for tokio runtime
    ///
    /// # Note
    /// If on_thread_start/stop are used somethere this can be overrided
    fn setup_global_task_monitor(&mut self, monitor: &TaskMonitor) -> &mut Self;
}

impl TokioBuilderExt for Builder {
    fn setup_global_task_monitor(&mut self, monitor: &TaskMonitor) -> &mut Self {
        self.on_thread_start({
            let monitor = monitor.clone();
            move || monitor.on_thread_start()
        })
        .on_thread_stop({
            let monitor = monitor.clone();
            move || monitor.on_thread_stop()
        })
    }
}

pub(crate) struct LoopWatcher {
    task_name: &'static str,
    monitor: TaskMonitor,
    immediate_poll_count: u64,
}

impl LoopWatcher {
    pub(crate) async fn step<Fut>(&mut self, step: Fut) -> Fut::Output
    where
        Fut: Future,
    {
        let max_polls = self
            .monitor
            .config
            .max_polls_immediately
            .unwrap_or(MonitorConfig::DEFAULT_MAX_POLLS_IMMEDIATELY);

        if self.immediate_poll_count > max_polls {
            self.immediate_poll_count = 0;
            self.monitor.report(MonitorEvent::TaskBusyLoop {
                name: self.task_name,
            });
            task::yield_now().await;
        }

        let mut step = std::pin::pin!(step);

        let mut poll_count = 0;
        poll_fn(|cx| {
            poll_count += 1;
            let poll = step.as_mut().poll(cx);

            if poll.is_ready() {
                if poll_count == 1 {
                    self.immediate_poll_count += 1;
                } else {
                    self.immediate_poll_count = 0;
                }
            }

            poll
        })
        .await
    }
}

thread_local! {
    static CURRENT_MONITOR: RefCell<Option<TaskMonitor>> = RefCell::new(None);
}

/// Get current handle as set in thread local
pub(crate) fn with_current_option<R>(f: impl FnOnce(Option<&TaskMonitor>) -> R) -> R {
    CURRENT_MONITOR.with(|mon| f(mon.borrow().as_ref()))
}

/// Calls inner fuction if current monitor exists
pub(crate) fn with_current<R>(f: impl FnOnce(&TaskMonitor) -> R) -> Option<R> {
    CURRENT_MONITOR.with(|mon| mon.borrow().as_ref().map(f))
}

#[cfg(test)]
mod test {
    use std::{
        future::pending,
        io,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    use async_trait::async_trait;
    use futures::{future::BoxFuture, Future};
    use telio_utils::time::sleep;
    use tokio::runtime::Builder;

    use crate::{task_exec, Runtime, RuntimeExt, StopResult, Task, WaitResponse};

    type Events = Arc<Mutex<Vec<MonitorEvent>>>;

    #[test]
    fn test_monitor_reports_busy_loop() {
        run_with_monitor(|_mon, events| async move {
            let task = Simple::start();

            task.set_busy_loop(true).await;
            sleep(Duration::from_millis(900)).await;

            {
                let events = events.lock().unwrap();
                assert_eq!(
                    &*events,
                    &[
                        MonitorEvent::TaskStart { name: "simple" },
                        MonitorEvent::TaskBusyLoop { name: "simple" }
                    ]
                );
            }

            let _ = task.stop().await;
        });
    }

    #[test]
    fn test_monitor_does_not_report_busy_loop_with_timeout() {
        run_with_monitor(|_mon, events| async move {
            let task = Simple::start();

            task.set_poll_loop(Duration::from_millis(1)).await;
            sleep(Duration::from_secs(2)).await;

            {
                let events = events.lock().unwrap();
                assert_eq!(&*events, &[MonitorEvent::TaskStart { name: "simple" }]);
            }

            let _ = task.stop().await;
        });
    }

    #[test]
    fn test_monitor_captures_manual_stop() {
        run_with_monitor(|_mon, events| async move {
            let task = Simple::start();
            let _ = task.stop().await;

            sleep(Duration::from_secs(1)).await;

            let events = events.lock().unwrap();
            assert_eq!(
                &*events,
                &[
                    MonitorEvent::TaskStart { name: "simple" },
                    MonitorEvent::TaskStop {
                        name: "simple",
                        reason: StopReason::Manual
                    }
                ]
            )
        });
    }

    #[test]
    fn test_monitor_captures_drop_stop() {
        run_with_monitor(|_mon, events| async move {
            {
                let _task = Simple::start();
            }

            sleep(Duration::from_secs(1)).await;

            let events = events.lock().unwrap();
            assert_eq!(
                &*events,
                &[
                    MonitorEvent::TaskStart { name: "simple" },
                    MonitorEvent::TaskStop {
                        name: "simple",
                        reason: StopReason::Dropped
                    }
                ]
            )
        });
    }

    #[test]
    fn test_monitor_captures_error_out() {
        run_with_monitor(|_mon, events| async move {
            let task = Simple::start();

            task.test_fail().await;

            sleep(Duration::from_secs(1)).await;

            {
                let events = events.lock().unwrap();
                assert_eq!(
                    &*events,
                    &[
                        MonitorEvent::TaskStart { name: "simple" },
                        MonitorEvent::TaskStop {
                            name: "simple",
                            reason: StopReason::Error("connection aborted".to_string())
                        },
                    ]
                );
            }

            let _ = task.stop().await;
        });
    }

    #[test]
    fn test_monitor_captures_panic_out() {
        run_with_monitor(|_mon, events| async move {
            let task = Simple::start();

            task.test_panic().await;

            sleep(Duration::from_secs(1)).await;

            {
                let events = events.lock().unwrap();
                assert_eq!(
                    &*events,
                    &[
                        MonitorEvent::TaskStart { name: "simple" },
                        MonitorEvent::TaskStop {
                            name: "simple",
                            reason: StopReason::Panic,
                        }
                    ]
                )
            }

            let _ = task.stop().await;
        });
    }

    fn run_with_monitor<F, Ft>(f: F) -> Events
    where
        F: FnOnce(TaskMonitor, Events) -> Ft,
        Ft: Future<Output = ()> + Send + 'static,
    {
        let events = Arc::new(Mutex::new(Vec::new()));

        let monitor = TaskMonitor::new(
            MonitorConfig {
                max_polls_immediately: Some(100),
                ..Default::default()
            },
            {
                let events = events.clone();
                move |event| {
                    let mut guard = events.lock().expect("no panic");
                    guard.push(event);
                }
            },
        );

        Builder::new_multi_thread()
            .enable_all()
            .setup_global_task_monitor(&monitor)
            .build()
            .unwrap()
            .block_on(f(monitor, events.clone()));

        events
    }

    struct Simple(Task<State>);
    #[derive(Default)]
    struct State {
        busy_loop: bool,
        poll_loop: Option<Duration>,
    }

    impl Simple {
        fn start() -> Self {
            Self(Task::start(State::default()))
        }

        async fn test_fail(&self) {
            let _ = task_exec!(&self.0, async move |_s| -> Result<(), io::Error> {
                Err(io::Error::from(io::ErrorKind::ConnectionAborted))
            })
            .await;
        }

        async fn test_panic(&self) {
            let _ = task_exec!(&self.0, async move |_s| -> Result<(), io::Error> {
                panic!("inner_pannic")
            })
            .await;
        }

        async fn set_busy_loop(&self, val: bool) {
            let _ = task_exec!(&self.0, async move |s| {
                s.busy_loop = val;
                Ok(())
            })
            .await;
        }

        async fn set_poll_loop(&self, interval: Duration) {
            let _ = task_exec!(&self.0, async move |s| {
                s.poll_loop = Some(interval);
                Ok(())
            })
            .await;
        }

        async fn stop(self) -> StopResult<io::Error> {
            self.0.stop().await
        }
    }

    #[async_trait]
    impl Runtime for State {
        const NAME: &'static str = "simple";

        type Err = io::Error;

        async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
            if self.busy_loop {
                Self::next()
            } else if let Some(time) = self.poll_loop {
                sleep(time).await;
                Self::next()
            } else {
                pending().await
            }
        }
    }
}
