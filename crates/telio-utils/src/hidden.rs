use std::{borrow::Borrow, fmt, ops, str::FromStr};

use serde::{Deserialize, Serialize};

/// Wraper type for values that contain sensitive information.
///
/// When printed in release mode it will not reveal inner data instead
/// replacing it with `****`.
#[derive(Default, Deserialize, Serialize, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Hidden<T>(pub T);

impl<T> fmt::Debug for Hidden<T>
where
    T: fmt::Debug,
{
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("****")
    }
}

impl<T> fmt::Display for Hidden<T>
where
    T: fmt::Display,
{
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("****")
    }
}

impl<T> From<T> for Hidden<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> FromStr for Hidden<T>
where
    T: FromStr,
{
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Hidden(T::from_str(s)?))
    }
}

impl<T> ops::Deref for Hidden<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> ops::DerefMut for Hidden<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Borrow<T> for Hidden<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T> PartialEq<T> for Hidden<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &T) -> bool {
        self.0.eq(other)
    }
}
