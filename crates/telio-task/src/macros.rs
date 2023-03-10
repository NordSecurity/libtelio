use futures::{future::BoxFuture, Future, FutureExt};

/// Helper function to box a future.
pub fn boxed<'a, F, O>(f: F) -> BoxFuture<'a, O>
where
    F: Future<Output = O> + Send + 'a,
{
    f.boxed()
}

/// Helper macro to write a more readable execution on task's state.
///
/// # Examples
/// ```ignore
/// // Full
/// let res: Result<ReturnType, ExecError> = task_exec(&task, async move |state: &mut TaskState| -> Result<ReturnType, TaskState::Err> {
///    // .. do something with state ..
///    Ok(ReturnType)
/// }).await;
/// ```
///
/// Argument type and return type can be skipped.
/// This macro transforms this async closure into:
///
/// ```ignore
/// task.exec(move |state: &mut TaskState| -> BoxFuture<Output=Result<ReturnType, TaskState::Err>> async move {
///    // .. do something with state ..
///    Ok(ReturnType)
/// }.boxed())
/// ```
#[macro_export]
macro_rules! task_exec {
    ($task:expr, async move |$s:ident| $body:expr) => {
        $crate::Task::exec($task, move |$s| $crate::boxed(async move { $body }))
    };

    ($task:expr, async move |$s:ident: $stype:ty| { $body:expr }) => {
        $crate::Task::exec($task, move |$s: $stype| $crate::boxed(async move { $body }))
    };

    ($task:expr, async move |$s:ident| -> $rtype:ty $body:block ) => {
        $crate::Task::exec($task, move |$s| -> BoxFuture<'_, $rtype> {
            $crate::boxed(async move { $body })
        })
    };

    ($task:expr, async move |$s:ident: $stype:ty| -> $rtype:ty $body:block ) => {
        $crate::Task::exec($task, move |$s: $stype| -> BoxFuture<'_, $rtype> {
            $crate::boxed(async move { $body })
        })
    };
}
