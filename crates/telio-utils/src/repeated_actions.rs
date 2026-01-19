use std::{
    collections::{hash_map, HashMap},
    hash::Hash,
    sync::Arc,
};
use thiserror::Error as ThisError;

use crate::{interval, interval_after};
use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};
use tokio::time::{Duration, Interval};

/// Possible [RepeatedAction] errors.
#[derive(ThisError, Debug)]
pub enum RepeatedActionError {
    /// Action is already added
    #[error("Repeated action already exists")]
    DuplicateRepeatedAction,
    /// Requested repeated action is not on the list
    #[error("Repeated action not found")]
    RepeatedActionNotFound,
    /// Actions list is empty
    #[error("No actions are added")]
    ListEmpty,
}

/// Single action type
pub type RepeatedAction<V, R> = Arc<dyn for<'a> Fn(&'a mut V) -> BoxFuture<'a, R> + Sync + Send>;
type Result<T> = std::result::Result<T, RepeatedActionError>;

/// Main struct container, that hold all actions
pub struct RepeatedActions<K, C, R> {
    actions: HashMap<K, (Interval, RepeatedAction<C, R>)>,
}

impl<K, C, R> Default for RepeatedActions<K, C, R>
where
    K: Eq + Hash + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, C, R> RepeatedActions<K, C, R>
where
    K: Eq + Hash + Send + Sync,
{
    /// Container's constructor
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Add single action (first tick is immediate)
    pub fn add_action(
        &mut self,
        key: K,
        dur: Duration,
        action: RepeatedAction<C, R>,
    ) -> Result<()> {
        if let hash_map::Entry::Vacant(e) = self.actions.entry(key) {
            e.insert((interval(dur), action));
            return Ok(());
        }

        Err(RepeatedActionError::DuplicateRepeatedAction)
    }

    /// Remove single action
    pub fn remove_action(&mut self, key: &K) -> Result<()> {
        self.actions.remove(key).map_or_else(
            || Err(RepeatedActionError::RepeatedActionNotFound),
            |_| Ok(()),
        )
    }

    /// Update interval (first tick is now() + dur)
    pub fn update_interval(&mut self, key: &K, dur: Duration) -> Result<()> {
        self.actions.get_mut(key).map_or_else(
            || Err(RepeatedActionError::RepeatedActionNotFound),
            |a| {
                a.0 = interval_after(dur, dur);
                Ok(())
            },
        )
    }

    /// Check if it contains action
    pub fn contains_action(&mut self, key: &K) -> bool {
        self.actions.contains_key(key)
    }

    /// Returns future (action), that will soon 'tick()'
    pub async fn select_action(&mut self) -> Result<(&K, RepeatedAction<C, R>)> {
        if self.actions.is_empty() {
            return Err(RepeatedActionError::ListEmpty);
        }

        // Collect futures
        let a = self
            .actions
            .iter_mut()
            .map(|(key, (interval, action))| (key, interval.tick(), action));

        // Transform futures to `Output = (key, action)`
        let mut b: FuturesUnordered<_> = a
            .map(|(key, interval, action)| interval.map(move |_| (key, action)).boxed())
            .collect();

        b.next()
            .await
            .ok_or(RepeatedActionError::RepeatedActionNotFound)
            .map(|(s, f)| (s, f.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instant;
    use maplit::hashset;
    use telio_test::assert_elapsed;
    use tokio::time;

    type Result = std::result::Result<(), ()>;

    pub struct Context {
        actions: RepeatedActions<String, Self, Result>,
        test: String,
    }

    impl Context {
        pub fn new(test: String) -> Self {
            Self {
                actions: RepeatedActions::<String, Self, Result>::new(),
                test,
            }
        }

        pub async fn print(&self, delay: Duration) -> Result {
            time::sleep(delay).await;
            println!("{}", self.test);
            Ok(())
        }

        pub async fn change(&mut self, str: String) -> Result {
            self.test = str;
            Ok(())
        }

        pub fn get(&self) -> &str {
            &self.test
        }
    }

    #[tokio::test]
    async fn add_remove_actions() {
        let mut ctx = Context::new("test".to_owned());

        let _ = ctx
            .actions
            .add_action(
                "action_0".to_owned(),
                Duration::from_secs(1),
                Arc::new(|s: _| Box::pin(async move { s.print(Duration::from_millis(100)).await })),
            )
            .unwrap();

        let dup = ctx.actions.add_action(
            "action_0".to_owned(),
            Duration::from_secs(1),
            Arc::new(|s: _| Box::pin(async move { s.print(Duration::from_millis(100)).await })),
        );

        assert!(dup.is_err());
        assert!(ctx.actions.contains_action(&"action_0".to_owned()));

        let remove = ctx.actions.remove_action(&"action_0".to_owned());

        assert!(remove.is_ok());
        assert!(!ctx.actions.contains_action(&"action_0".to_owned()));
    }

    #[tokio::test(start_paused = true)]
    async fn execute_action_after_a_long_sleep_shouldnt_call_all_the_missed_actions() {
        let start = Arc::new(Instant::now());
        let mut ctx = Context::new("test".to_owned());

        ctx.actions
            .add_action(
                "action_0".to_owned(),
                Duration::from_secs(1),
                Arc::new({
                    let start = start.clone();
                    move |s: _| {
                        Box::pin({
                            let start = start.clone();
                            async move {
                                println!("hello at {:?}", start.elapsed());
                                s.change("change_0".to_owned()).await
                            }
                        })
                    }
                }),
            )
            .unwrap();

        time::advance(Duration::from_secs(3)).await;

        for _ in 0..3 {
            ctx.actions.select_action().await.unwrap().1(&mut ctx)
                .await
                .unwrap();
        }

        // Wait 3s, execute 3 actions every 1s (first one immediately after the sleep) gives 5s at least.
        // With the default interval missed tick behaviour, all 3 actions execute immediately after the
        // sleep ending right after 3s.
        assert!(start.elapsed() >= Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn execute_actions() {
        let mut ctx = Context::new("test".to_owned());

        ctx.actions
            .add_action(
                "action_0".to_owned(),
                Duration::from_millis(100),
                Arc::new(|s: _| Box::pin(async move { s.change("change_0".to_owned()).await })),
            )
            .unwrap();

        ctx.actions
            .add_action(
                "action_1".to_owned(),
                Duration::from_millis(150),
                Arc::new(|s: _| Box::pin(async move { s.change("change_1".to_owned()).await })),
            )
            .unwrap();

        // First ticks immediatelly
        let _ = ctx.actions.select_action().await.unwrap();
        let _ = ctx.actions.select_action().await.unwrap();

        let start = Instant::now();

        {
            time::advance(Duration::from_millis(100)).await;
            assert_elapsed!(start, Duration::from_millis(100), Duration::from_millis(10));
            let (key, action) = ctx.actions.select_action().await.unwrap();
            let key = key.clone();
            let _ = action(&mut ctx).await;
            assert_eq!(ctx.test, "change_0".to_owned());
            assert_eq!(*key, "action_0".to_owned());
        }
        {
            time::advance(Duration::from_millis(50)).await;
            assert_elapsed!(start, Duration::from_millis(150), Duration::from_millis(10));
            let (key, action) = ctx.actions.select_action().await.unwrap();
            let key = key.clone();
            let _ = action(&mut ctx).await;
            assert_eq!(ctx.test, "change_1".to_owned());
            assert_eq!(*key, "action_1".to_owned());
        }
        {
            time::advance(Duration::from_millis(50)).await;
            assert_elapsed!(start, Duration::from_millis(200), Duration::from_millis(10));
            let (key, action) = ctx.actions.select_action().await.unwrap();
            let key = key.clone();
            let _ = action(&mut ctx).await;
            assert_eq!(ctx.test, "change_0".to_owned());
            assert_eq!(*key, "action_0".to_owned());
        }
        {
            // Both actions should run since 300ms
            time::advance(Duration::from_millis(100)).await;
            assert_elapsed!(start, Duration::from_millis(300), Duration::from_millis(10));

            let (key1, action1) = ctx.actions.select_action().await.unwrap();
            let key1 = key1.clone();
            let _ = action1(&mut ctx).await;
            let change1 = ctx.test.clone();

            let (key2, action2) = ctx.actions.select_action().await.unwrap();
            let key2 = key2.clone();
            let _ = action2(&mut ctx).await;
            let change2 = ctx.test.clone();
            let keys = hashset! {key1, key2};
            let changes = hashset! {change1, change2};

            assert_eq!(
                hashset! {"change_0".to_owned(), "change_1".to_owned()},
                changes
            );
            assert_eq!(
                hashset! {"action_0".to_owned(), "action_1".to_owned()},
                keys
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn update_action_interval() {
        let mut ctx = Context::new("test".to_owned());

        ctx.actions
            .add_action(
                "action_0".to_owned(),
                Duration::from_millis(100),
                Arc::new(|s: _| Box::pin(async move { s.change("change_0".to_owned()).await })),
            )
            .unwrap();

        let mut cnt = 0;
        // Start positions with some error tollerance
        let mut start_0 = time::Instant::now();

        // First ticks immediatelly
        let _ = ctx.actions.select_action().await.unwrap();

        let _ = tokio::spawn(async move {
            loop {
                if cnt == 0 {
                    time::advance(Duration::from_millis(100)).await;
                }

                let (key, action) = ctx.actions.select_action().await.unwrap();
                let key = key.clone();
                let _ = action(&mut ctx).await;

                if cnt == 0 {
                    assert_eq!(ctx.test, "change_0".to_owned());
                    assert_eq!(*key, "action_0".to_owned());
                    assert_elapsed!(
                        start_0,
                        Duration::from_millis(100),
                        Duration::from_millis(10)
                    );

                    ctx.actions
                        .update_interval(&key, Duration::from_millis(200))
                        .unwrap();

                    start_0 = time::Instant::now();
                    time::advance(Duration::from_millis(200)).await;
                } else {
                    assert_eq!(*key, "action_0".to_owned());
                    assert_elapsed!(
                        start_0,
                        Duration::from_millis(200),
                        Duration::from_millis(10)
                    );

                    break;
                }

                cnt += 1;
            }
        })
        .await
        .unwrap();
    }
}
