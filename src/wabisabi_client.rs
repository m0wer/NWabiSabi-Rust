//! Client-side WabiSabi credential protocol.
//!
//! Mirrors `WalletWasabi.WabiSabi.Crypto.WabiSabiClient`. Both the zero
//! and real-amount paths share a single Fiat-Shamir transcript labelled
//! `UnifiedRegistration/{N}/{isNull}` that flows from request build into
//! response verification.

use crate::constants::{CREDENTIAL_NUMBER, RANGE_PROOF_WIDTH};
use crate::credential_requesting::{
    CredentialsResponse, CredentialsResponseValidation, IssuanceRequest,
    IssuanceValidationData, RealCredentialsRequest, ZeroCredentialsRequest,
};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::{CredentialIssuerParameters, Scalar};
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::{
    statements::{
        balance_proof_knowledge, issuer_parameters_statement, range_proof_knowledge,
        show_credential_knowledge,
    },
    Credential, ProofSystem, Transcript,
};

/// Build the canonical request transcript for a `WabiSabi` registration.
///
/// Matches C# `BuildTranscript`:
///   `UnifiedRegistration/{NumberOfCredentials}/{isNullRequest}`.
fn build_transcript(is_null: bool) -> Transcript {
    let label = format!(
        "UnifiedRegistration/{}/{}",
        CREDENTIAL_NUMBER,
        if is_null { "True" } else { "False" }
    );
    Transcript::new(label.as_bytes())
}

/// Client-side API for WabiSabi credential protocol.
pub struct WabiSabiClient {
    coordinator_parameters: CredentialIssuerParameters,
    range_proof_width: usize,
}

impl WabiSabiClient {
    /// Create a new client bound to a coordinator's public parameters.
    pub fn new(coordinator_parameters: CredentialIssuerParameters) -> Self {
        Self {
            coordinator_parameters,
            range_proof_width: RANGE_PROOF_WIDTH,
        }
    }

    /// Override the range-proof width (default `RANGE_PROOF_WIDTH`).
    pub fn with_range_proof_width(mut self, width: usize) -> Self {
        self.range_proof_width = width;
        self
    }

    /// Override the range-proof width to fit `max_amount`. Mirrors the
    /// coordinator's `with_max_amount`.
    pub fn with_max_amount(mut self, max_amount: i64) -> Self {
        self.range_proof_width = if max_amount <= 0 {
            0
        } else {
            (i64::BITS - max_amount.leading_zeros()) as usize
        };
        self
    }

    /// Range-proof width currently configured on this client.
    pub fn range_proof_width(&self) -> usize {
        self.range_proof_width
    }

    /// Coordinator parameters this client was instantiated against.
    pub fn coordinator_parameters(&self) -> &CredentialIssuerParameters {
        &self.coordinator_parameters
    }

    /// Build a request for `CREDENTIAL_NUMBER` zero-value (bootstrap)
    /// credentials.
    ///
    /// Returns the request together with the validation state needed to
    /// verify the coordinator's response on the same transcript.
    pub fn create_request_for_zero_amount<R: WabiSabiRandom>(
        &self,
        random: &mut R,
    ) -> Result<(ZeroCredentialsRequest, CredentialsResponseValidation)> {
        let mut requested = Vec::with_capacity(CREDENTIAL_NUMBER);
        let mut knowledge_list = Vec::with_capacity(CREDENTIAL_NUMBER);
        let mut validation_data = Vec::with_capacity(CREDENTIAL_NUMBER);

        for _ in 0..CREDENTIAL_NUMBER {
            // Width-0 range proof: Ma = 0*Gg + r*Gh. `range_proof_knowledge`
            // returns the empty bit-commitments vector for width 0.
            let randomness = random.get_scalar();
            let (knowledge, ma, bit_commitments) =
                range_proof_knowledge(0u64, randomness.clone(), 0, random)?;
            knowledge_list.push(knowledge);
            requested.push(IssuanceRequest::new(ma.clone(), bit_commitments));
            validation_data.push(IssuanceValidationData::new(0, randomness, ma));
        }

        let mut transcript = build_transcript(true);
        let proofs = ProofSystem::prove(&mut transcript, &knowledge_list, random)?;

        let request = ZeroCredentialsRequest::new(requested, proofs);
        let validation = CredentialsResponseValidation::new(transcript, validation_data);
        Ok((request, validation))
    }

    /// Build a real-amount credential request.
    ///
    /// `amounts` length must equal `CREDENTIAL_NUMBER`.
    /// `credentials_to_present` are the previously issued credentials being
    /// spent in this round (input registration uses zero-value credentials,
    /// reissuance presents real ones).
    pub fn create_request<R: WabiSabiRandom>(
        &self,
        amounts: &[u64],
        credentials_to_present: Vec<Credential>,
        random: &mut R,
    ) -> Result<(RealCredentialsRequest, CredentialsResponseValidation)> {
        if amounts.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }
        for c in &credentials_to_present {
            if c.value() < 0 {
                return Err(WabiSabiError::Unspecified);
            }
        }

        // delta = sum(requested) - sum(presented) (i64; may be negative).
        let requested_sum: i64 = amounts.iter().map(|&a| a as i64).sum();
        let presented_sum: i64 = credentials_to_present.iter().map(|c| c.value()).sum();
        let delta = requested_sum.checked_sub(presented_sum).ok_or(WabiSabiError::Unspecified)?;

        let mut presentations = Vec::with_capacity(credentials_to_present.len());
        let mut knowledge_list = Vec::new();
        let mut z_sum = Scalar::zero();
        let mut presented_randomness_sum = Scalar::zero();

        for credential in &credentials_to_present {
            let z = random.get_scalar();
            let presentation = credential.present(&z)?;
            knowledge_list.push(show_credential_knowledge(
                &presentation,
                &z,
                credential.value(),
                credential.randomness(),
                &credential.mac().t,
                &self.coordinator_parameters,
            )?);
            z_sum = z_sum + z;
            presented_randomness_sum = presented_randomness_sum + credential.randomness().clone();
            presentations.push(presentation);
        }

        let mut requested = Vec::with_capacity(CREDENTIAL_NUMBER);
        let mut validation_data = Vec::with_capacity(CREDENTIAL_NUMBER);
        let mut requested_randomness_sum = Scalar::zero();

        for &amount in amounts {
            let randomness = random.get_scalar();
            let (knowledge, ma, bit_commitments) =
                range_proof_knowledge(amount, randomness.clone(), self.range_proof_width, random)?;
            knowledge_list.push(knowledge);
            requested.push(IssuanceRequest::new(ma.clone(), bit_commitments));
            validation_data.push(IssuanceValidationData::new(amount as i64, randomness.clone(), ma));
            requested_randomness_sum = requested_randomness_sum + randomness;
        }

        // deltaR = sum(presented_r) - sum(requested_r) = sum(cr) + (-sum(r)).
        let r_delta_sum = presented_randomness_sum + requested_randomness_sum.negate();
        knowledge_list.push(balance_proof_knowledge(z_sum, r_delta_sum)?);

        // Soundness: every Knowledge must satisfy its statement before proving.
        #[cfg(debug_assertions)]
        for (i, k) in knowledge_list.iter().enumerate() {
            k.assert_soundness().unwrap_or_else(|e| {
                panic!("client knowledge {i} unsound: {e:?}");
            });
        }

        let mut transcript = build_transcript(false);
        let proofs = ProofSystem::prove(&mut transcript, &knowledge_list, random)?;

        let request = RealCredentialsRequest::new(delta, presentations, requested, proofs);
        let validation = CredentialsResponseValidation::new(transcript, validation_data);
        Ok((request, validation))
    }

    /// Verify the coordinator's MAC issuance proofs and produce the new
    /// `Credential` set. The provided `validation` must be the value
    /// returned by the matching `create_request_*` call.
    pub fn handle_response(
        &self,
        response: &CredentialsResponse,
        validation: CredentialsResponseValidation,
    ) -> Result<Vec<Credential>> {
        let CredentialsResponseValidation { mut transcript, validation_data } = validation;

        let issued_macs = response.issued_credentials();
        let proofs = response.proofs();

        if issued_macs.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }
        if proofs.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfProofs);
        }
        if validation_data.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }

        let mut statements = Vec::with_capacity(CREDENTIAL_NUMBER);
        for (mac, vd) in issued_macs.iter().zip(validation_data.iter()) {
            statements.push(issuer_parameters_statement(
                &self.coordinator_parameters,
                mac,
                &vd.ma,
            )?);
        }

        if !ProofSystem::verify(&mut transcript, &statements, proofs)? {
            return Err(WabiSabiError::InvalidMacProofs);
        }

        let mut credentials = Vec::with_capacity(CREDENTIAL_NUMBER);
        for (mac, vd) in issued_macs.iter().zip(validation_data.into_iter()) {
            credentials.push(Credential::new(vd.value, vd.randomness, mac.clone())?);
        }
        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;
    use crate::crypto::CredentialIssuerSecretKey;

    #[test]
    fn test_create_zero_request() {
        let mut random = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut random);
        let params = sk.compute_parameters().unwrap();
        let client = WabiSabiClient::new(params);

        let (request, validation) = client.create_request_for_zero_amount(&mut random).unwrap();

        use crate::credential_requesting::CredentialsRequest;
        assert_eq!(request.requested().len(), CREDENTIAL_NUMBER);
        assert_eq!(validation.validation_data.len(), CREDENTIAL_NUMBER);
        assert_eq!(request.delta(), 0);
        assert_eq!(request.presented().len(), 0);
    }
}
