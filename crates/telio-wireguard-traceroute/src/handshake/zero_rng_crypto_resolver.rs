use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};

/// Custom CryptoResolver that always returns ZeroRng
/// This allows for fully deterministic packet generation in tests
pub struct ZeroRngCryptoResolver;

impl CryptoResolver for ZeroRngCryptoResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(ZeroRng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

/// Zero RNG - always returns zeros
/// Useful for deterministic testing
#[derive(Debug, Clone, Copy)]
struct ZeroRng;

impl Random for ZeroRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        dest.fill(0);
        Ok(())
    }
}
