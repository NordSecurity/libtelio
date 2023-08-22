use std::mem::replace;

use futures::{
    stream::{ReuniteError, SplitSink, SplitStream},
    Sink, Stream, StreamExt,
};

/// Helper to split / join Stream + Sink type.
pub struct InOut<T, I>(Inner<T, I>);

enum Inner<T, I> {
    Joined(T),
    Split(SplitSink<T, I>, SplitStream<T>),
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
    pub fn split(&mut self) -> Option<(&mut SplitSink<T, I>, &mut SplitStream<T>)> {
        self.in_place(Self::into_split);
        match &mut self.0 {
            Split(tx, rx) => Some((tx, rx)),
            _ => None,
        }
    }

    /// Get reference to joined type
    pub fn joined(&mut self) -> Result<Option<&mut T>, ReuniteError<T, I>> {
        self.try_in_place(Self::into_joined)?;
        Ok(match &mut self.0 {
            Joined(j) => Some(j),
            _ => None,
        })
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

    fn into_joined(self) -> Result<Self, ReuniteError<T, I>> {
        Ok(match self {
            Self(Split(tx, rx)) => Self(Joined(tx.reunite(rx)?)),
            v => v,
        })
    }

    #[inline(always)]
    fn in_place(&mut self, map: impl FnOnce(Self) -> Self) {
        *self = map(replace(self, Self(Empty)));
    }

    #[inline(always)]
    fn try_in_place(
        &mut self,
        map: impl FnOnce(Self) -> Result<Self, ReuniteError<T, I>>,
    ) -> Result<(), ReuniteError<T, I>> {
        *self = map(replace(self, Self(Empty)))?;
        Ok(())
    }
}
