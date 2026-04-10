use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Insecure random number generator for testing only
/// DO NOT USE IN PRODUCTION
#[derive(Debug, Clone)]
pub struct InsecureRandom {
    rng: StdRng,
}

impl InsecureRandom {
    /// Create a new insecure random number generator from a seed
    pub fn from_seed(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Create with fixed seed for deterministic testing
    pub fn deterministic() -> Self {
        Self::from_seed(0)
    }
}

impl RngCore for InsecureRandom {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::WabiSabiRandom;

    #[test]
    fn test_insecure_random_deterministic() {
        let mut rng1 = InsecureRandom::deterministic();
        let mut rng2 = InsecureRandom::deterministic();

        let s1 = rng1.get_scalar();
        let s2 = rng2.get_scalar();

        // Should generate same scalar with same seed
        assert_eq!(s1, s2);
    }
}
