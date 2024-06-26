use rand::{rngs::mock::StepRng, CryptoRng, RngCore};

/// Mocked random number generator for creating not-random results
pub struct CryptoStepRng(pub StepRng);

impl RngCore for CryptoStepRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for CryptoStepRng {}
