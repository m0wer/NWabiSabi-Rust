use crate::crypto::{GroupElement, GroupElementVector, Scalar, ScalarVector};
use crate::error::Result;
use crate::zero_knowledge::linear_relation::Equation;

/// Represents a public statement in a zero-knowledge proof
///
/// A statement consists of multiple equations that all share the same witness.
/// The prover demonstrates knowledge of a witness that satisfies all equations.
#[derive(Clone, Debug)]
pub struct Statement {
    pub equations: Vec<Equation>,
}

impl Statement {
    /// Create a new statement from a single equation
    pub fn new(public_point: GroupElement, generators: Vec<GroupElement>) -> Self {
        let equation = Equation::new(public_point, GroupElementVector::new(generators));
        Self {
            equations: vec![equation],
        }
    }

    /// Create a statement from multiple equations
    pub fn from_equations(equations: Vec<Equation>) -> Self {
        assert!(!equations.is_empty(), "Statement must have at least one equation");
        Self { equations }
    }

    /// Create a statement from a matrix representation
    ///
    /// Each row is an equation: [public_point, generator_1, generator_2, ...]
    /// None values are treated as the point at infinity
    pub fn from_matrix(matrix: Vec<Vec<Option<GroupElement>>>) -> Self {
        assert!(!matrix.is_empty(), "Matrix must have at least one row");

        let infinity = GroupElement::infinity();

        let equations = matrix
            .into_iter()
            .map(|row| {
                assert!(row.len() >= 2, "Each row must have at least one generator and one public point");

                let public_point = row[0].clone().unwrap_or_else(|| infinity.clone());
                let generators: Vec<GroupElement> = row[1..]
                    .iter()
                    .map(|g| g.clone().unwrap_or_else(|| infinity.clone()))
                    .collect();

                Equation::new(public_point, GroupElementVector::new(generators))
            })
            .collect();

        Self { equations }
    }

    /// Get all public points from equations
    pub fn public_points(&self) -> Vec<&GroupElement> {
        self.equations
            .iter()
            .map(|eq| &eq.public_point)
            .collect()
    }

    /// Get all generators from all equations
    pub fn generators(&self) -> Vec<&GroupElement> {
        self.equations
            .iter()
            .flat_map(|eq| eq.generators.iter())
            .collect()
    }

    /// Check if the verification equation holds for all equations
    pub fn check_verification_equation(
        &self,
        public_nonces: &GroupElementVector,
        challenge: &Scalar,
        responses: &ScalarVector,
    ) -> Result<bool> {
        // Number of public nonces must match number of equations
        if public_nonces.len() != self.equations.len() {
            return Ok(false);
        }

        // Check each equation
        for (equation, nonce) in self.equations.iter().zip(public_nonces.iter()) {
            if !equation.verify(nonce, challenge, responses)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::Generators;

    #[test]
    fn test_statement_creation() {
        let g = Generators::g().clone();
        let p = GroupElement::infinity();

        let statement = Statement::new(p, vec![g]);
        assert_eq!(statement.equations.len(), 1);
    }

    #[test]
    fn test_statement_from_matrix() {
        let g = Generators::g().clone();
        let h = Generators::gh().clone();

        let matrix = vec![
            vec![Some(GroupElement::infinity()), Some(g.clone()), Some(h.clone())],
            vec![Some(GroupElement::infinity()), Some(g.clone()), None],
        ];

        let statement = Statement::from_matrix(matrix);
        assert_eq!(statement.equations.len(), 2);
        assert_eq!(statement.equations[0].generators.len(), 2);
    }

    #[test]
    fn test_statement_verification() {
        let mut rng = SecureRandom::new();

        // Simple statement P = x*G
        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g.clone()]);

        // Create proof data
        let k = rng.get_scalar();
        let r = (&k * &g).unwrap();
        let e = rng.get_scalar();

        let witness = ScalarVector::new(vec![x]);
        let nonces = ScalarVector::new(vec![k]);
        let responses = Equation::respond(&witness, &nonces, &e).unwrap();

        let public_nonces = GroupElementVector::new(vec![r]);

        assert!(statement
            .check_verification_equation(&public_nonces, &e, &responses)
            .unwrap());
    }
}

