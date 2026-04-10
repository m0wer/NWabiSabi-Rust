use crate::crypto::{GroupElement, GroupElementVector, Scalar, ScalarVector};
use crate::error::{Result, WabiSabiError};

/// Represents a linear equation over group elements
///
/// Knowledge of representation asserts:
///     P = x_1*G_1 + x_2*G_2 + ... + x_n*G_n
///
/// where:
/// - P is the public point
/// - G_i are the generators
/// - x_i are the witness scalars (secret)
#[derive(Clone, Debug)]
pub struct Equation {
    /// The public point P
    pub public_point: GroupElement,
    /// The generators [G_1, G_2, ..., G_n]
    pub generators: GroupElementVector,
}

impl Equation {
    /// Create a new equation
    pub fn new(public_point: GroupElement, generators: GroupElementVector) -> Self {
        Self {
            public_point,
            generators,
        }
    }

    /// Verify the equation holds for the given proof data
    ///
    /// Verification equation: sG = R + eP
    /// where:
    /// - R is the public nonce (kG, k is secret nonce)
    /// - P is the public input (xG, x is secret)
    /// - e is the challenge
    /// - s is the response
    pub fn verify(
        &self,
        public_nonce: &GroupElement,
        challenge: &Scalar,
        responses: &ScalarVector,
    ) -> Result<bool> {
        // A challenge of 0 does not place any constraint on the witness
        if challenge.is_zero() {
            return Ok(false);
        }

        // Verification equation: s*G = R + e*P
        // Left side: responses * generators
        let lhs = (responses * &self.generators)?;

        // Right side: public_nonce + challenge * public_point
        let challenge_times_public = self.public_point.multiply(challenge)?;
        let rhs = (public_nonce.clone() + challenge_times_public)?;

        Ok(lhs == rhs)
    }

    /// Respond to a challenge given witness and secret nonces
    ///
    /// Formula: s = k + e*x
    /// where:
    /// - k is the secret nonce
    /// - e is the challenge
    /// - x is the witness
    pub fn respond(
        witness: &ScalarVector,
        secret_nonces: &ScalarVector,
        challenge: &Scalar,
    ) -> Result<ScalarVector> {
        // All secret nonces must be non-zero
        for nonce in secret_nonces.iter() {
            if nonce.is_zero() {
                return Err(WabiSabiError::Unspecified);
            }
        }

        // s = k + e*x
        let challenge_times_witness = *challenge * witness.clone();
        secret_nonces.clone() + challenge_times_witness
    }

    /// Check if a witness solves the equation
    pub fn check_solution(&self, witness: &ScalarVector) -> Result<()> {
        let result = (witness * &self.generators)?;
        if result != self.public_point {
            return Err(WabiSabiError::Unspecified);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::Generators;

    #[test]
    fn test_equation_verification() {
        let mut rng = SecureRandom::new();

        // Create a simple equation P = x*G
        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let equation = Equation::new(p, GroupElementVector::new(vec![g.clone()]));

        // Secret nonce k
        let k = rng.get_scalar();
        let r = (&k * &g).unwrap(); // Public nonce R = k*G

        // Challenge e
        let e = rng.get_scalar();

        // Response s = k + e*x
        let witness = ScalarVector::new(vec![x]);
        let nonces = ScalarVector::new(vec![k]);
        let responses = Equation::respond(&witness, &nonces, &e).unwrap();

        // Verify
        assert!(equation.verify(&r, &e, &responses).unwrap());
    }

    #[test]
    fn test_equation_check_solution() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let equation = Equation::new(p, GroupElementVector::new(vec![g]));
        let witness = ScalarVector::new(vec![x]);

        assert!(equation.check_solution(&witness).is_ok());
    }

    #[test]
    fn test_zero_challenge_fails_verification() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let p = GroupElement::infinity();
        let equation = Equation::new(p, GroupElementVector::new(vec![g]));

        let r = GroupElement::infinity();
        let responses = ScalarVector::new(vec![rng.get_scalar()]);

        let result = equation.verify(&r, &Scalar::zero(), &responses).unwrap();
        assert!(!result); // Zero challenge should fail
    }
}
