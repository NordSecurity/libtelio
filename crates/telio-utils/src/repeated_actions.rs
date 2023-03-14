use std::collections::{hash_map, HashMap};
use thiserror::Error as ThisError;

use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};
use tokio::time::{interval, Duration, Interval};

/// Possible [RepeatedAction] errors.
#[derive(ThisError, Debug)]
pub enum Error {
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

/// Single aaction type
pub type RepeatedAction<V, R> = for<'a> fn(&'a mut V) -> BoxFuture<'a, R>;
type Action<C, R> = (String, (Interval, RepeatedAction<C, R>));
type Result<T> = std::result::Result<T, Error>;

/// Main struct container, that hold all actions
pub struct RepeatedActions<C, R> {
    actions: HashMap<String, (Interval, RepeatedAction<C, R>)>,
}

impl<C, R> Default for RepeatedActions<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, R> RepeatedActions<C, R> {
    /// Container's constructor
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Add single action
    pub fn add_action(
        &mut self,
        name: String,
        dur: Duration,
        action: RepeatedAction<C, R>,
    ) -> Result<()> {
        if let hash_map::Entry::Vacant(e) = self.actions.entry(name) {
            e.insert((interval(dur), action));
            return Ok(());
        }

        Err(Error::DuplicateRepeatedAction)
    }

    #[allow(dead_code)]
    /// Remove single action
    pub fn remove_action(&mut self, name: String) -> Result<()> {
        self.actions
            .remove(&name)
            .map_or_else(|| Err(Error::RepeatedActionNotFound), |_| Ok(()))
    }

    /// Returns future (action), that will soon 'tick()'
    pub async fn select_action(&mut self) -> Result<(String, RepeatedAction<C, R>)> {
        if self.actions.is_empty() {
            return Err(Error::ListEmpty);
        }

        // Collect futures
        let a = self
            .actions
            .iter_mut()
            .map(|(name, (interval, action))| (name, interval.tick(), action));

        // Transform futures to `Output = (name, action)`
        #[allow(clippy::type_complexity)]
        let mut b: FuturesUnordered<_> = a
            .map(|(name, interval, action)| interval.map(move |_| (name.clone(), action)).boxed())
            .into_iter()
            .collect();

        b.next()
            .await
            .ok_or(Error::RepeatedActionNotFound)
            .map(|(s, f)| (s, *f))
    }
}

impl<C, R, const N: usize> From<[Action<C, R>; N]> for RepeatedActions<C, R> {
    fn from(arr: [Action<C, R>; N]) -> Self {
        RepeatedActions::<C, R> {
            actions: HashMap::from(arr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::time;

    type Result = std::result::Result<(), ()>;

    /// Calculates elapsed time with defined rounding
    macro_rules! assert_elapsed {
        ($start:expr, $dur:expr, $round:expr) => {{
            let elapsed = $start.elapsed();
            let lower: std::time::Duration = $dur;
            let round: std::time::Duration = $round;

            assert!(
                elapsed >= lower - round && elapsed <= lower + round,
                "actual = {:?}, expected = {:?}",
                elapsed,
                lower,
            );
        }};
    }

    pub struct Context {
        actions: RepeatedActions<Self, Result>,
        test: String,
    }

    impl Context {
        pub fn new(test: String) -> Self {
            Self {
                actions: RepeatedActions::<Self, Result>::new(),
                test,
            }
        }

        pub async fn print(&self, delay: Duration) -> Result {
            time::sleep(delay).await;
            println!("{}", self.test);
            Ok(())
        }

        pub async fn change(&mut self, delay: Duration, str: String) -> Result {
            time::sleep(delay).await;
            self.test = str;
            Ok(())
        }
    }

    #[tokio::test]
    async fn add_remove_actions() {
        let mut ctx = Context::new("test".to_owned());

        let _ = ctx
            .actions
            .add_action("action_0".to_owned(), Duration::from_secs(1), |s| {
                Box::pin(async move { s.print(Duration::from_millis(100)).await })
            })
            .unwrap();

        let dup = ctx
            .actions
            .add_action("action_0".to_owned(), Duration::from_secs(1), |s| {
                Box::pin(async move { s.print(Duration::from_millis(100)).await })
            });

        assert!(dup.is_err());

        let remove = ctx.actions.remove_action("action_0".to_owned());

        assert!(remove.is_ok());
    }

    #[tokio::test]
    #[ignore = "flaky test (time measure)"]
    async fn execute_actions() {
        let mut ctx = Context::new("test".to_owned());

        ctx.actions
            .add_action("action_0".to_owned(), Duration::from_millis(100), |s| {
                Box::pin(async move {
                    s.change(Duration::from_millis(1), "change_0".to_owned())
                        .await
                })
            })
            .unwrap();

        ctx.actions
            .add_action("action_1".to_owned(), Duration::from_millis(150), |s| {
                Box::pin(async move {
                    s.change(Duration::from_millis(1), "change_1".to_owned())
                        .await
                })
            })
            .unwrap();

        let mut cnt = 0;
        // Start positions with some error tollerance
        let mut start_0 = Instant::now();
        let mut start_1 = Instant::now();

        // First ticks immediatelly
        let _ = ctx.actions.select_action().await.unwrap();
        let _ = ctx.actions.select_action().await.unwrap();

        loop {
            let (name, action) = ctx.actions.select_action().await.unwrap();
            let _ = action(&mut ctx).await;

            if cnt % 2 == 0 {
                assert_eq!(ctx.test, "change_0".to_owned());
                assert_eq!(name, "action_0".to_owned());
                assert_elapsed!(
                    start_0,
                    Duration::from_millis(100),
                    Duration::from_millis(10)
                );
                start_0 = Instant::now();
            } else {
                assert_eq!(ctx.test, "change_1".to_owned());
                assert_eq!(name, "action_1".to_owned());
                assert_elapsed!(
                    start_1,
                    Duration::from_millis(150),
                    Duration::from_millis(10)
                );
                start_1 = Instant::now();
            }

            cnt += 1;

            // We'll test just 4 iterations
            if cnt > 3 {
                break;
            }
        }
    }
}
