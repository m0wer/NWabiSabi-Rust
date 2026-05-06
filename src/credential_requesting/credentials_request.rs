use crate::credential_requesting::IssuanceRequest;
use crate::zero_knowledge::{CredentialPresentation, Proof};
use serde::{Deserialize, Serialize};

/// Trait for all credential request types
pub trait CredentialsRequest {
    /// The difference between the sum of requested and presented credentials
    ///
    /// - Positive: input registration (depositing)
    /// - Negative: output registration (withdrawing)
    /// - Zero: reissuance or zero-value credential request
    fn delta(&self) -> i64;

    /// Randomized credentials presented (for output registration or reissuance)
    fn presented(&self) -> &[CredentialPresentation];

    /// Credential issuance requests
    fn requested(&self) -> &[IssuanceRequest];

    /// Accompanying proofs (range proofs, balance proofs, etc.)
    fn proofs(&self) -> &[Proof];
}

/// Request for zero-value credentials (bootstrap)
///
/// Used to obtain initial credentials with zero value that can later be
/// exchanged for real-value credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroCredentialsRequest {
    /// Issuance requests for zero-value credentials
    requested: Vec<IssuanceRequest>,
    /// Proofs that the requested amounts are zero
    proofs: Vec<Proof>,
}

impl ZeroCredentialsRequest {
    /// Create a new zero credentials request
    pub fn new(requested: Vec<IssuanceRequest>, proofs: Vec<Proof>) -> Self {
        Self { requested, proofs }
    }
}

impl CredentialsRequest for ZeroCredentialsRequest {
    fn delta(&self) -> i64 {
        0 // Zero-value credentials don't change balance
    }

    fn presented(&self) -> &[CredentialPresentation] {
        &[] // No credentials are presented in a bootstrap request
    }

    fn requested(&self) -> &[IssuanceRequest] {
        &self.requested
    }

    fn proofs(&self) -> &[Proof] {
        &self.proofs
    }
}

/// Request for real-value credentials
///
/// Used to exchange credentials, either:
/// - Input registration: Present zero-value credentials, request value credentials (positive delta)
/// - Output registration: Present value credentials, request zero-value credentials (negative delta)
/// - Reissuance: Present and request credentials with same total value (zero delta)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealCredentialsRequest {
    /// Delta between requested and presented credential values
    delta: i64,
    /// Credentials being presented (spent/reissued)
    presented: Vec<CredentialPresentation>,
    /// New credentials being requested
    requested: Vec<IssuanceRequest>,
    /// Proofs (balance proof, range proofs, credential presentation proofs)
    proofs: Vec<Proof>,
}

impl RealCredentialsRequest {
    /// Create a new real credentials request
    pub fn new(
        delta: i64,
        presented: Vec<CredentialPresentation>,
        requested: Vec<IssuanceRequest>,
        proofs: Vec<Proof>,
    ) -> Self {
        Self {
            delta,
            presented,
            requested,
            proofs,
        }
    }
}

impl CredentialsRequest for RealCredentialsRequest {
    fn delta(&self) -> i64 {
        self.delta
    }

    fn presented(&self) -> &[CredentialPresentation] {
        &self.presented
    }

    fn requested(&self) -> &[IssuanceRequest] {
        &self.requested
    }

    fn proofs(&self) -> &[Proof] {
        &self.proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::GroupElement;
    use crate::crypto::{Generators, GroupElementVector, ScalarVector};

    #[test]
    fn test_zero_credentials_request() {
        let mut rng = SecureRandom::new();
        let ma = GroupElement::infinity();
        let request = IssuanceRequest::new(ma, vec![]);

        // Build a syntactically valid (but unverified) proof: at least one
        // non-infinity public nonce and at least one response. This exercises
        // the request container, not the proof system.
        let nonce_scalar = rng.get_scalar();
        let nonce_point = (&nonce_scalar * Generators::gg()).unwrap();
        let nonces = GroupElementVector::new(vec![nonce_point]);
        let responses = ScalarVector::new(vec![rng.get_scalar()]);
        let proof = Proof::new(nonces, responses);

        let zero_request = ZeroCredentialsRequest::new(vec![request], vec![proof]);

        assert_eq!(zero_request.delta(), 0);
        assert_eq!(zero_request.presented().len(), 0);
        assert_eq!(zero_request.requested().len(), 1);
        assert_eq!(zero_request.proofs().len(), 1);
    }

    #[test]
    fn test_real_credentials_request() {
        let presented = vec![];
        let requested = vec![];
        let proofs = vec![];

        let real_request = RealCredentialsRequest::new(10_000, presented, requested, proofs);

        assert_eq!(real_request.delta(), 10_000);
        assert_eq!(real_request.presented().len(), 0);
        assert_eq!(real_request.requested().len(), 0);
        assert_eq!(real_request.proofs().len(), 0);
    }
}
