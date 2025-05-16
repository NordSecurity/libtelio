use std::{borrow::Borrow, fmt, net::SocketAddr, ops, str::FromStr};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A trait that makes it possible to set the backing memory of type to all zeros.
/// This is a local copy of the zeroize::Zeroize trait, so that it's possible to
/// provide implementations for external types (like SocketAddr).
/// All implementations should use Zeroize crate.
pub trait LocalZeroize {
    /// Zero out this object from memory using Rust intrinsics which ensure the zeroization operation is not “optimized away” by the compiler.
    fn zeroize(&mut self);
}

impl<const N: usize> LocalZeroize for [u8; N] {
    fn zeroize(&mut self) {
        Zeroize::zeroize(self);
    }
}

impl LocalZeroize for String {
    fn zeroize(&mut self) {
        Zeroize::zeroize(self);
    }
}

impl LocalZeroize for SocketAddr {
    fn zeroize(&mut self) {
        // Safety:
        // - The type must not contain references to outside data or dynamically sized data, such as Vec<T> or String.
        //   - both ipv4 and ipv6 variants contain only [u8; N], u16 or u32
        // - Values stored in the type must not have Drop impls.
        //   - both ipv6 and ipv4 variants don't have Drop impls. This will not change, as removal of Drop is considered a breaking change, see for example: https://github.com/tokio-rs/tracing/issues/2578
        // - This function can invalidate the type if it is used after this function is called on it. It is advisable to call this function only in impl Drop.
        //   - zeroize is only called in Hidden::drop
        // - The bit pattern of all zeroes must be valid for the data being zeroized. This may not be true for enums and pointers.
        //   - since both variants contain only u16, u32 and arrays of u8, bit pattern of all zeros is a valid bit pattern. This is why `zeroize_flat_type` is not
        //     called on the SocketAddr, but it's first matched to avoid question of validity of all zeros pattern for enum

        match self {
            SocketAddr::V4(socket_addr_v4) => unsafe {
                zeroize::zeroize_flat_type(socket_addr_v4);
            },
            SocketAddr::V6(socket_addr_v6) => unsafe {
                zeroize::zeroize_flat_type(socket_addr_v6);
            },
        }
    }
}

impl<T: LocalZeroize> LocalZeroize for Option<T> {
    fn zeroize(&mut self) {
        if let Some(v) = self {
            v.zeroize()
        }
    }
}

/// Wraper type for values that contain sensitive information.
///
/// When printed in release mode it will not reveal inner data instead
/// replacing it with `****`.
#[derive(Default, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Hidden<T: LocalZeroize>(pub T);

impl<T: LocalZeroize> Drop for Hidden<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: LocalZeroize> ZeroizeOnDrop for Hidden<T> {}

/// Type alias for UniFFI
pub type HiddenString = Hidden<String>;

impl<T: LocalZeroize> fmt::Debug for Hidden<T>
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

impl<T: LocalZeroize> fmt::Display for Hidden<T>
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

impl<T: LocalZeroize> From<T> for Hidden<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: LocalZeroize> FromStr for Hidden<T>
where
    T: FromStr,
{
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Hidden(T::from_str(s)?))
    }
}

impl<T: LocalZeroize> ops::Deref for Hidden<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: LocalZeroize> ops::DerefMut for Hidden<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: LocalZeroize> AsRef<T> for Hidden<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: LocalZeroize> AsMut<T> for Hidden<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: LocalZeroize> Borrow<T> for Hidden<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T: LocalZeroize> PartialEq<T> for Hidden<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &T) -> bool {
        self.0.eq(other)
    }
}
