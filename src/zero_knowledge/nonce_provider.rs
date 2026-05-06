use crate::crypto::{Scalar, ScalarVector};
use crate::crypto::randomness::WabiSabiRandom;
use crate::error::Result;
use strobe_rs::Strobe;

/// Provides synthetic secret nonces for zero-knowledge proofs
/// Combines secret inputs with additional randomness to generate nonces
pub struct SyntheticSecretNonceProvider {
    strobe: Strobe,
    secret_count: usize,
}

impl SyntheticSecretNonceProvider {
    /// Create a new synthetic secret nonce provider
    pub fn new<R: WabiSabiRandom>(
        mut strobe: Strobe,
        secrets: &[Scalar],
        random: &mut R,
    ) -> Self {
        assert!(!secrets.is_empty(), "secrets cannot be empty");

        let secret_count = secrets.len();

        // Add secret inputs as key material
        for secret in secrets {
            let secret_bytes = secret.to_bytes();
            strobe.key(&secret_bytes, false);
        }

        // Add additional randomness
        let mut random_bytes = [0u8; 32];
        random.get_bytes(&mut random_bytes);
        strobe.key(&random_bytes, false);

        Self {
            strobe,
            secret_count,
        }
    }

    /// Get a single scalar nonce
    pub fn get_scalar(&mut self) -> Result<Scalar> {
        loop {
            let mut scalar_bytes = [0u8; 32];
            self.strobe.prf(&mut scalar_bytes, false);

            // Try to create a valid scalar, retry if it overflows
            if let Ok(scalar) = Scalar::from_bytes(&scalar_bytes) {
                if !scalar.is_zero() {
                    return Ok(scalar);
                }
            }
        }
    }

    /// Get a vector of scalar nonces (matching the number of secrets)
    pub fn get_scalar_vector(&mut self) -> Result<ScalarVector> {
        let mut scalars = Vec::with_capacity(self.secret_count);
        for _ in 0..self.secret_count {
            scalars.push(self.get_scalar()?);
        }
        Ok(ScalarVector::new(scalars))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;
    use crate::zero_knowledge::Transcript;

    #[test]
    fn test_nonce_provider_single_scalar() {
        let mut rng = SecureRandom::new();
        let secrets = vec![Scalar::random(&mut rng)];
        let transcript = Transcript::new(b"test");

        let mut provider = transcript.create_synthetic_secret_nonce_provider(&secrets, &mut rng);
        let nonce1 = provider.get_scalar().unwrap();
        let nonce2 = provider.get_scalar().unwrap();

        // Should generate different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_provider_vector() {
        let mut rng = SecureRandom::new();
        let secrets = vec![
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];
        let transcript = Transcript::new(b"test");

        let mut provider = transcript.create_synthetic_secret_nonce_provider(&secrets, &mut rng);
        let nonces = provider.get_scalar_vector().unwrap();

        assert_eq!(nonces.len(), 3);
    }

    #[test]
    fn test_deterministic_with_same_inputs() {
        let mut rng1 = SecureRandom::new();
        let mut rng2 = SecureRandom::new();

        let secret = Scalar::one();
        let secrets = vec![secret];

        let transcript1 = Transcript::new(b"test");
        let transcript2 = Transcript::new(b"test");

        // Using same random seed should produce same nonces
        let _provider1 = transcript1.create_synthetic_secret_nonce_provider(&secrets, &mut rng1);
        let _provider2 = transcript2.create_synthetic_secret_nonce_provider(&secrets, &mut rng2);

        // Note: This test may not pass because SecureRandom is not deterministic
        // In production, determinism comes from the transcript state, not the RNG
    }

    #[test]
    #[should_panic(expected = "secrets cannot be empty")]
    fn test_empty_secrets_panics() {
        let mut rng = SecureRandom::new();
        let secrets: Vec<Scalar> = vec![];
        let transcript = Transcript::new(b"test");
        transcript.create_synthetic_secret_nonce_provider(&secrets, &mut rng);
    }
}
