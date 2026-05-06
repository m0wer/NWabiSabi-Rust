//! Per-request client-side validation state.
//!
//! When a client builds a credential request, the prover advances a
//! Fiat-Shamir transcript across all sub-proofs. When the coordinator's
//! response arrives, the client must verify the issuance proofs on the
//! *same* transcript (which by then has additionally absorbed the
//! coordinator's MAC issuance proof commitments). Mirrors C#
//! `CredentialsResponseValidation`.

use crate::crypto::{GroupElement, Scalar};
use crate::zero_knowledge::Transcript;

/// Per-credential validation data: the value, randomness, and Ma the
/// client used when constructing the request, used after issuance to
/// reconstruct `Credential` instances and to bind issuance proofs to the
/// requested attribute.
#[derive(Clone, Debug)]
pub struct IssuanceValidationData {
    pub value: i64,
    pub randomness: Scalar,
    pub ma: GroupElement,
}

impl IssuanceValidationData {
    pub fn new(value: i64, randomness: Scalar, ma: GroupElement) -> Self {
        Self { value, randomness, ma }
    }
}

/// State the client retains between request and response.
///
/// Holds the prover transcript snapshot at the point where it has
/// finished proving the request side; the coordinator continues from
/// the same state.
#[derive(Clone)]
pub struct CredentialsResponseValidation {
    pub transcript: Transcript,
    pub validation_data: Vec<IssuanceValidationData>,
}

impl CredentialsResponseValidation {
    pub fn new(transcript: Transcript, validation_data: Vec<IssuanceValidationData>) -> Self {
        Self { transcript, validation_data }
    }
}
