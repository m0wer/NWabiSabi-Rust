use crate::crypto::GroupElement;
use serde::{Deserialize, Serialize};

/// Represents a request for issuing a new credential
///
/// Contains:
/// - Ma: Pedersen commitment to the credential amount
/// - BitCommitments: Pedersen commitments to the amount's binary decomposition (for range proofs)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// Pedersen commitment to the credential amount: Ma = a*Gg + r*Gh
    pub ma: GroupElement,
    /// Pedersen commitments to the binary decomposition of the amount (for range proofs)
    pub bit_commitments: Vec<GroupElement>,
}

impl IssuanceRequest {
    /// Create a new issuance request
    pub fn new(ma: GroupElement, bit_commitments: Vec<GroupElement>) -> Self {
        Self {
            ma,
            bit_commitments,
        }
    }

    /// Get the Pedersen commitment Ma
    pub fn ma(&self) -> &GroupElement {
        &self.ma
    }

    /// Get the bit commitments
    pub fn bit_commitments(&self) -> &[GroupElement] {
        &self.bit_commitments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuance_request_creation() {
        let ma = GroupElement::infinity();
        let bit_commitments = vec![GroupElement::infinity()];

        let request = IssuanceRequest::new(ma.clone(), bit_commitments.clone());

        assert_eq!(request.ma(), &ma);
        assert_eq!(request.bit_commitments().len(), 1);
    }
}
