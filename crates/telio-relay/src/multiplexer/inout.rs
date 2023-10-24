use std::mem::replace;

use futures::{
    stream::{SplitSink, SplitStream},
    Sink, Stream, StreamExt,
};

/// Helper to split / join Stream + Sink type.
pub struct InOut<T, I>(Inner<T, I>);

enum Inner<T, I> {
    Joined(T),
    Split(SplitSink<T, I>, SplitStream<T>),
    // This is only allowed to be used for a short time while we are
    // remapping self into other state
    Empty,
}
use Inner::*;

impl<T, I> InOut<T, I>
where
    T: Stream<Item = I> + Sink<I> + Unpin,
{
    /// Create new inout helper
    pub fn new(chan: T) -> Self {
        Self(Joined(chan))
    }

    /// Get references to split halves
    pub fn split(&mut self) -> (&mut SplitSink<T, I>, &mut SplitStream<T>) {
        self.in_place(Self::into_split);
        match &mut self.0 {
            Split(tx, rx) => (tx, rx),
            _ => unreachable!("After in_place(Self::into_split) self will always be split"),
        }
    }

    /// Get reference to joined type
    pub fn joined(&mut self) -> &mut T {
        self.in_place(Self::into_joined);

        match &mut self.0 {
            Joined(j) => j,
            _ => unreachable!("into_join enusures self will always be Joined"),
        }
    }

    fn into_split(self) -> Self {
        match self {
            Self(Joined(j)) => {
                let (tx, rx) = j.split();
                Self(Split(tx, rx))
            }
            v => v,
        }
    }

    fn into_joined(self) -> Self {
        match self {
            Self(Split(tx, rx)) => Self(Joined(match tx.reunite(rx) {
                Ok(v) => v,
                Err(_) => {
                    unreachable!("We are always working with the same channel in this struct")
                }
            })),
            v => v,
        }
    }

    #[inline(always)]
    fn in_place(&mut self, map: impl FnOnce(Self) -> Self) {
        let new = map(replace(self, Self(Empty)));
        assert!(
            !matches!(new.0, Inner::Empty),
            "Map is not allowed to map to Empty, it would break invariance"
        );
        *self = new;
    }
}
