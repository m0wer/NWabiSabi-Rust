pub mod secure_random;
pub mod insecure_random;

pub use secure_random::SecureRandom;
pub use insecure_random::InsecureRandom;

use crate::crypto::Scalar;
use rand::Rng;

/// Trait for random number generation
pub trait WabiSabiRandom: Rng + Sized {
    /// Generate a random scalar
    fn get_scalar(&mut self) -> Scalar {
        Scalar::random(self)
    }

    /// Fill a buffer with random bytes
    fn get_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest)
    }
}

impl<R: Rng + Sized> WabiSabiRandom for R {}
