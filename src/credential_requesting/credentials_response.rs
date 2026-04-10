use crate::crypto::Mac;
use crate::zero_knowledge::Proof;
use serde::{Deserialize, Serialize};

/// Response message from coordinator containing issued credentials
///
/// Contains `k` issued MACs and corresponding proofs that they were
/// issued using the coordinator's secret key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsResponse {
    /// MACs issued by the coordinator
    issued_credentials: Vec<Mac>,
    /// Proofs that the credentials were issued correctly
    proofs: Vec<Proof>,
}

impl CredentialsResponse {
    /// Create a new credentials response
    pub fn new(issued_credentials: Vec<Mac>, proofs: Vec<Proof>) -> Self {
        Self {
            issued_credentials,
            proofs,
        }
    }

    /// Get the issued credentials (MACs)
    pub fn issued_credentials(&self) -> &[Mac] {
        &self.issued_credentials
    }

    /// Get the proofs
    pub fn proofs(&self) -> &[Proof] {
        &self.proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{GroupElement, Scalar};

    #[test]
    fn test_credentials_response_creation() {
        let t = Scalar::one();
        let v = GroupElement::infinity();
        let mac = Mac::new(t, v).unwrap();

        let response = CredentialsResponse::new(vec![mac], vec![]);

        assert_eq!(response.issued_credentials().len(), 1);
        assert_eq!(response.proofs().len(), 0);
    }
}
