use crate::crypto::{GroupElementVector, ScalarVector};
use serde::{Deserialize, Serialize};

/// A zero-knowledge proof consisting of public nonces and responses
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Public nonces (commitments): R_i = k_i * G_i
    pub public_nonces: GroupElementVector,
    /// Responses: s_i = k_i + e * x_i
    pub responses: ScalarVector,
}

impl Proof {
    /// Create a new proof
    pub fn new(public_nonces: GroupElementVector, responses: ScalarVector) -> Self {
        assert!(!public_nonces.is_empty(), "public_nonces cannot be empty");
        assert!(!responses.is_empty(), "responses cannot be empty");

        // Check that no public nonces are infinity
        for nonce in public_nonces.iter() {
            assert!(!nonce.is_infinity(), "public nonces cannot be infinity");
        }

        Self {
            public_nonces,
            responses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::{GroupElement, Generators};

    #[test]
    fn test_proof_creation() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let k = rng.get_scalar();
        let r = (&k * &g).unwrap();

        let nonces = GroupElementVector::new(vec![r]);
        let responses = ScalarVector::new(vec![rng.get_scalar()]);

        let proof = Proof::new(nonces, responses);
        assert_eq!(proof.public_nonces.len(), 1);
        assert_eq!(proof.responses.len(), 1);
    }

    #[test]
    #[should_panic(expected = "public_nonces cannot be empty")]
    fn test_proof_empty_nonces_panics() {
        let nonces = GroupElementVector::new(vec![]);
        let responses = ScalarVector::new(vec![]);
        Proof::new(nonces, responses);
    }

    #[test]
    #[should_panic(expected = "public nonces cannot be infinity")]
    fn test_proof_infinity_nonce_panics() {
        let nonces = GroupElementVector::new(vec![GroupElement::infinity()]);
        let mut rng = SecureRandom::new();
        let responses = ScalarVector::new(vec![rng.get_scalar()]);
        Proof::new(nonces, responses);
    }
}
