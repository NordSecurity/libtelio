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
/// The value returned by the closure is handed back to the caller as is.
/// An `Err` returned from the closure is a regular value for the caller, it does not stop the task.
///
/// # Examples
/// ```ignore
/// // Full
/// let res: Result<ReturnType, ExecError> = task_exec(&task, async move |state: &mut TaskState| -> ReturnType {
///    // .. do something with state ..
///    ReturnType
/// }).await;
/// ```
///
/// Argument type and return type can be skipped.
/// This macro transforms this async closure into:
///
/// ```ignore
/// task.exec(move |state: &mut TaskState| -> BoxFuture<Output=ReturnType> async move {
///    // .. do something with state ..
///    ReturnType
/// }.boxed())
/// ```
#[macro_export]
macro_rules! task_exec {
    ($task:expr, $($closure:tt)+) => {
        $crate::__task_exec!(exec, $task, $($closure)+)
    };
}

/// Same as [task_exec], but the closure returns [ExecOutcome](crate::ExecOutcome).
///
/// [ExecOutcome::StopTask](crate::ExecOutcome::StopTask) stops the task with the given error
/// and the caller gets [ExecError](crate::ExecError).
#[macro_export]
macro_rules! task_exec_or_stop {
    ($task:expr, $($closure:tt)+) => {
        $crate::__task_exec!(exec_or_stop, $task, $($closure)+)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __task_exec {
    ($method:ident, $task:expr, async move |$s:ident| $body:expr) => {
        $crate::Task::$method($task, move |$s| $crate::boxed(async move { $body }))
    };

    ($method:ident, $task:expr, async move |$s:ident: $stype:ty| { $body:expr }) => {
        $crate::Task::$method($task, move |$s: $stype| $crate::boxed(async move { $body }))
    };

    ($method:ident, $task:expr, async move |$s:ident| -> $rtype:ty $body:block ) => {
        $crate::Task::$method($task, move |$s| -> BoxFuture<'_, $rtype> {
            $crate::boxed(async move { $body })
        })
    };

    ($method:ident, $task:expr, async move |$s:ident: $stype:ty| -> $rtype:ty $body:block ) => {
        $crate::Task::$method($task, move |$s: $stype| -> BoxFuture<'_, $rtype> {
            $crate::boxed(async move { $body })
        })
    };
}
