use std::{
    cmp::Ordering,
    fmt::{self, Display},
};

/// Generation of a packet.
///
/// This allows to track intentional route changes from other side.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Generation(pub u8);

impl Generation {
    /// Get next generation.
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl PartialOrd for Generation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.0 == other.0 {
            Some(Ordering::Equal)
        } else if other.0.wrapping_sub(self.0) > u8::MAX / 2 {
            Some(Ordering::Greater)
        } else {
            Some(Ordering::Less)
        }
    }
}

impl Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gen({})", &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iteration() {
        let mut gen = Generation::default();
        for _ in 0..((1 << 9) + 10) {
            gen = gen.next();
        }
        assert_eq!(Generation(10), gen);
    }

    #[test]
    fn test_continuous_comparison() {
        let mut gen = Generation::default();
        for _ in 0..(1 << 9) {
            let next = gen.next();
            assert!(gen < next);
            gen = next;
        }
    }

    #[test]
    fn test_same_values() {
        for n in 0..=u8::MAX {
            assert_eq!(Generation(n), Generation(n));
            assert_eq!(
                Generation(n).partial_cmp(&Generation(n)),
                Some(Ordering::Equal)
            );
        }
    }

    #[test]
    fn test_critical_cmp() {
        let mid = u8::MAX / 2;
        for n in 0..=u8::MAX {
            let gen = Generation(n);
            let gen_mid = Generation(n.wrapping_add(mid));
            let gen_mid_prev = Generation(n.wrapping_add(mid - 1));
            let gen_mid_next = Generation(n.wrapping_add(mid + 1));
            assert!(gen < gen_mid);
            assert!(gen < gen_mid_prev);
            assert!(gen > gen_mid_next);
        }
    }
}
