use crate::crypto::{Scalar, ScalarVector};
use crate::error::Result;
use crate::zero_knowledge::linear_relation::{Equation, Statement};

/// Represents the private witness (knowledge) in a zero-knowledge proof
///
/// Combines a public statement with the secret witness that satisfies it.
#[derive(Clone, Debug)]
pub struct Knowledge {
    pub statement: Statement,
    pub witness: ScalarVector,
}

impl Knowledge {
    /// Create new knowledge from a statement and witness
    pub fn new(statement: Statement, witness: ScalarVector) -> Result<Self> {
        // Check that witness size matches the generators in the first equation
        // (all equations share the same witness structure)
        if let Some(first_eq) = statement.equations.first() {
            if witness.len() != first_eq.generators.len() {
                return Err(crate::error::WabiSabiError::Unspecified);
            }
        }

        Ok(Self { statement, witness })
    }

    /// Respond to a challenge using the witness and secret nonces
    pub fn respond_to_challenge(
        &self,
        challenge: &Scalar,
        secret_nonces: &ScalarVector,
    ) -> Result<ScalarVector> {
        Equation::respond(&self.witness, secret_nonces, challenge)
    }

    /// Assert that the witness actually solves all equations in the statement
    /// (for testing purposes)
    pub fn assert_soundness(&self) -> Result<()> {
        for equation in &self.statement.equations {
            equation.check_solution(&self.witness)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::{GroupElement, GroupElementVector, Generators};

    #[test]
    fn test_knowledge_creation() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let witness = ScalarVector::new(vec![x]);

        let knowledge = Knowledge::new(statement, witness).unwrap();
        assert!(knowledge.assert_soundness().is_ok());
    }

    #[test]
    fn test_knowledge_respond_to_challenge() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let witness = ScalarVector::new(vec![x]);
        let knowledge = Knowledge::new(statement, witness).unwrap();

        let k = rng.get_scalar();
        let nonces = ScalarVector::new(vec![k]);
        let challenge = rng.get_scalar();

        let responses = knowledge.respond_to_challenge(&challenge, &nonces).unwrap();
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn test_knowledge_wrong_witness_fails() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let wrong_x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let wrong_witness = ScalarVector::new(vec![wrong_x]);

        let knowledge = Knowledge::new(statement, wrong_witness).unwrap();
        assert!(knowledge.assert_soundness().is_err());
    }
}

