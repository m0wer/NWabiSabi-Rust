use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

/// Cryptographically secure random number generator
#[derive(Debug, Clone)]
pub struct SecureRandom {
    rng: OsRng,
}

impl SecureRandom {
    /// Create a new secure random number generator
    pub fn new() -> Self {
        Self { rng: OsRng }
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRandom {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Scalar;
    use crate::crypto::randomness::WabiSabiRandom;

    #[test]
    fn test_secure_random_scalar() {
        let mut rng = SecureRandom::new();
        let s1 = rng.get_scalar();
        let s2 = rng.get_scalar();
        // Probability of collision is negligible
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_secure_random_bytes() {
        let mut rng = SecureRandom::new();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.get_bytes(&mut buf1);
        rng.get_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }
}
