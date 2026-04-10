use crate::crypto::{GroupElement, GroupElementVector, Scalar};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul};

/// Vector of scalars with batch operations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarVector(Vec<Scalar>);

impl ScalarVector {
    /// Create a new scalar vector
    pub fn new(scalars: Vec<Scalar>) -> Self {
        Self(scalars)
    }

    /// Create from slice
    pub fn from_slice(scalars: &[Scalar]) -> Self {
        Self(scalars.to_vec())
    }

    /// Get the number of scalars
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get scalar at index
    pub fn get(&self, index: usize) -> Option<&Scalar> {
        self.0.get(index)
    }

    /// Iterator over scalars
    pub fn iter(&self) -> impl Iterator<Item = &Scalar> {
        self.0.iter()
    }

    /// Convert to inner vector
    pub fn into_inner(self) -> Vec<Scalar> {
        self.0
    }

    /// Reference to inner vector
    pub fn as_slice(&self) -> &[Scalar] {
        &self.0
    }
}

impl FromIterator<Scalar> for ScalarVector {
    fn from_iter<I: IntoIterator<Item = Scalar>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Add for ScalarVector {
    type Output = Result<Self>;

    fn add(self, other: Self) -> Self::Output {
        if self.len() != other.len() {
            return Err(crate::error::WabiSabiError::Unspecified);
        }

        Ok(Self(
            self.0
                .into_iter()
                .zip(other.0)
                .map(|(a, b)| a + b)
                .collect(),
        ))
    }
}

impl Mul<ScalarVector> for Scalar {
    type Output = ScalarVector;

    fn mul(self, vector: ScalarVector) -> Self::Output {
        ScalarVector(vector.0.into_iter().map(|s| self * s).collect())
    }
}

impl Mul<&GroupElementVector> for &ScalarVector {
    type Output = Result<GroupElement>;

    fn mul(self, ge_vec: &GroupElementVector) -> Self::Output {
        if self.len() != ge_vec.len() {
            return Err(crate::error::WabiSabiError::Unspecified);
        }

        let secp = secp256k1::Secp256k1::new();
        let mut result = GroupElement::infinity();

        for (scalar, ge) in self.iter().zip(ge_vec.iter()) {
            let term = ge.multiply(scalar)?;
            result = (result + term)?;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_scalar_vector_creation() {
        let scalars = vec![Scalar::one(), Scalar::zero()];
        let vec = ScalarVector::new(scalars.clone());
        assert_eq!(vec.len(), 2);
        assert_eq!(vec.get(0), Some(&Scalar::one()));
    }

    #[test]
    fn test_scalar_vector_addition() {
        let v1 = ScalarVector::new(vec![Scalar::one(), Scalar::zero()]);
        let v2 = ScalarVector::new(vec![Scalar::one(), Scalar::one()]);
        let result = (v1 + v2).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_scalar_mul_vector() {
        let scalar = Scalar::one();
        let vec = ScalarVector::new(vec![Scalar::one(), Scalar::zero()]);
        let result = scalar * vec;
        assert_eq!(result.len(), 2);
    }
}
