use core::convert::Infallible;
use rand::rand_core::TryRng;
use rand::TryCryptoRng;

/// A simple step RNG for testing (replacement for removed `rand::rngs::mock::StepRng`).
/// Yields an arithmetic sequence: initial_value, initial_value+increment, ...
///
/// Adapted from the rand 0.10 internal test helper:
/// <https://github.com/rust-random/rand/blob/0.10.0/src/lib.rs#L351-L369>
#[derive(Clone)]
pub struct StepRng(u64, u64);

impl StepRng {
    /// Create a new [`StepRng`] with the given initial value and increment.
    pub fn new(initial_value: u64, increment: u64) -> Self {
        StepRng(initial_value, increment)
    }
}

impl TryRng for StepRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.try_next_u64().map(|x| x as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let res = self.0;
        self.0 = self.0.wrapping_add(self.1);
        Ok(res)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        rand::rand_core::utils::fill_bytes_via_next_word(dest, || self.try_next_u64())
    }
}

/// Mocked random number generator for creating not-random results.
/// Wraps [`StepRng`] and marks it as cryptographically suitable (for testing only).
pub struct CryptoStepRng(pub StepRng);

impl TryRng for CryptoStepRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.0.try_fill_bytes(dest)
    }
}

impl TryCryptoRng for CryptoStepRng {}
// CryptoRng is blanket-implemented for any TryCryptoRng + TryRng<Error=Infallible>
