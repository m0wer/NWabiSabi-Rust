//! Coordinator-side credential issuer.
//!
//! Mirrors `WalletWasabi.WabiSabi.Crypto.CredentialIssuer`. Verification
//! and MAC-issuance proofs share a single Fiat-Shamir transcript labelled
//! `UnifiedRegistration/{N}/{isNull}` to bind the request and response
//! together (matches `WabiSabiClient`).

use crate::constants::{CREDENTIAL_NUMBER, RANGE_PROOF_WIDTH};
use crate::credential_requesting::{
    CredentialsRequest, CredentialsResponse, IssuanceRequest,
};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::{CredentialIssuerParameters, CredentialIssuerSecretKey, Mac};
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::{
    statements::{
        balance_proof_statement, issuance_request_statement, issuer_parameters_knowledge,
        show_credential_statement, zero_proof_statement,
    },
    Knowledge, ProofSystem, Statement, Transcript,
};
use crate::Generators;
use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

fn build_transcript(is_null: bool) -> Transcript {
    let label = format!(
        "UnifiedRegistration/{}/{}",
        CREDENTIAL_NUMBER,
        if is_null { "True" } else { "False" }
    );
    Transcript::new(label.as_bytes())
}

/// Coordinator-side credential issuer with thread-safe state management.
///
/// Tracks balance and prevents double-spending via serial-number tracking.
pub struct CredentialIssuer {
    secret_key: CredentialIssuerSecretKey,
    parameters: CredentialIssuerParameters,
    balance: Arc<AtomicI64>,
    serial_numbers: Arc<Mutex<HashSet<Vec<u8>>>>,
    range_proof_width: usize,
    max_amount: i64,
}

impl CredentialIssuer {
    /// Create a new credential issuer with the supplied initial balance.
    pub fn new(secret_key: CredentialIssuerSecretKey, initial_balance: i64) -> Result<Self> {
        let parameters = secret_key.compute_parameters()?;
        Ok(Self {
            secret_key,
            parameters,
            balance: Arc::new(AtomicI64::new(initial_balance)),
            serial_numbers: Arc::new(Mutex::new(HashSet::new())),
            range_proof_width: RANGE_PROOF_WIDTH,
            max_amount: (1u64 << RANGE_PROOF_WIDTH).saturating_sub(1) as i64,
        })
    }

    /// Override the range-proof width accepted by this issuer.
    pub fn with_range_proof_width(mut self, width: usize) -> Self {
        self.range_proof_width = width;
        self.max_amount = if width >= 63 {
            i64::MAX
        } else {
            ((1u64 << width) - 1) as i64
        };
        self
    }

    /// Override the maximum amount accepted by this issuer; the range-proof
    /// width is recomputed to the minimum number of bits needed to represent
    /// `max_amount` (matches C# `CredentialIssuer` behaviour).
    pub fn with_max_amount(mut self, max_amount: i64) -> Self {
        let width = if max_amount <= 0 {
            0
        } else {
            (i64::BITS - max_amount.leading_zeros()) as usize
        };
        self.range_proof_width = width;
        self.max_amount = max_amount;
        self
    }

    /// Range-proof width currently configured on this issuer.
    pub fn range_proof_width(&self) -> usize {
        self.range_proof_width
    }

    /// Maximum credential amount accepted by this issuer.
    pub fn max_amount(&self) -> i64 {
        self.max_amount
    }

    pub fn parameters(&self) -> &CredentialIssuerParameters {
        &self.parameters
    }

    pub fn balance(&self) -> i64 {
        self.balance.load(Ordering::SeqCst)
    }

    /// Validate a request, update issuer state, and produce the response.
    pub fn handle_request<R: WabiSabiRandom>(
        &self,
        request: &dyn CredentialsRequest,
        random: &mut R,
    ) -> Result<CredentialsResponse> {
        let delta = request.delta();
        let presented = request.presented();
        let requested = request.requested();
        let proofs = request.proofs();

        if requested.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfRequestedCredentials {
                expected: CREDENTIAL_NUMBER,
                actual: requested.len(),
            });
        }

        // Heuristic for null requests: matches the client constructor.
        let is_null = presented.is_empty()
            && delta == 0
            && requested.iter().all(|r| r.bit_commitments().is_empty());

        // Real (non-null) requests must present exactly CREDENTIAL_NUMBER credentials.
        if !is_null && presented.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfPresentedCredentials {
                expected: CREDENTIAL_NUMBER,
                actual: presented.len(),
            });
        }

        if !is_null && delta.abs() > self.max_amount {
            return Err(WabiSabiError::InvalidAmount);
        }

        // Each non-null requested credential must carry exactly `range_proof_width` bit commitments.
        if !is_null {
            for req in requested {
                if req.bit_commitments().len() != self.range_proof_width {
                    return Err(WabiSabiError::InvalidBitCommitment);
                }
            }
        }

        // Balance check (delta is added to coordinator, subtracted from client).
        let current_balance = self.balance.load(Ordering::SeqCst);
        let new_balance = current_balance
            .checked_add(delta)
            .ok_or(WabiSabiError::Unspecified)?;
        if new_balance < 0 {
            return Err(WabiSabiError::NegativeBalance(new_balance));
        }

        // Double-spend detection on presented serial numbers.
        let serial_numbers: Vec<Vec<u8>> = presented
            .iter()
            .map(|p| p.s().to_bytes().to_vec())
            .collect();
        {
            let mut sorted = serial_numbers.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() != serial_numbers.len() {
                return Err(WabiSabiError::SerialNumberAlreadyUsed);
            }
            let seen = self.serial_numbers.lock().unwrap();
            for s in &serial_numbers {
                if seen.contains(s) {
                    return Err(WabiSabiError::SerialNumberAlreadyUsed);
                }
            }
        }

        // Verify request proofs and issue MACs on the same transcript.
        let mut transcript = build_transcript(is_null);

        let request_statements = self.build_request_statements(request, is_null)?;
        if request_statements.len() != proofs.len() {
            return Err(WabiSabiError::CoordinatorReceivedInvalidProofs);
        }
        if !ProofSystem::verify(&mut transcript, &request_statements, proofs)? {
            return Err(WabiSabiError::CoordinatorReceivedInvalidProofs);
        }

        // Issue MACs on the now-advanced transcript.
        let (issued, issuance_knowledge) = self.issue_macs(requested, random)?;
        let issuance_proofs = ProofSystem::prove(&mut transcript, &issuance_knowledge, random)?;

        // Commit state mutations only after every check passed.
        self.balance.store(new_balance, Ordering::SeqCst);
        {
            let mut seen = self.serial_numbers.lock().unwrap();
            for s in serial_numbers {
                seen.insert(s);
            }
        }

        Ok(CredentialsResponse::new(issued, issuance_proofs))
    }

    /// Construct verification statements in the canonical C# order:
    /// presentations → range/zero proofs → balance proof.
    fn build_request_statements(
        &self,
        request: &dyn CredentialsRequest,
        is_null: bool,
    ) -> Result<Vec<Statement>> {
        let presented = request.presented();
        let requested = request.requested();
        let mut statements: Vec<Statement> =
            Vec::with_capacity(presented.len() + requested.len() + 1);

        for presentation in presented {
            let z_point = presentation.compute_z(&self.secret_key)?;
            statements.push(show_credential_statement(presentation, &z_point, &self.parameters));
        }

        let width = if is_null { 0 } else { self.range_proof_width };
        for req in requested {
            statements.push(if is_null {
                zero_proof_statement(req.ma().clone())
            } else {
                issuance_request_statement(req, width)
            });
        }

        if !is_null {
            // Balance commitment B = delta·Gg + sum(Ca) - sum(Ma)  (matches C# CredentialIssuer.cs:213)
            let mut bal = crate::crypto::GroupElement::infinity();
            if request.delta() != 0 {
                let delta_scalar = crate::crypto::Scalar::from_i64(request.delta());
                bal = (bal + (&delta_scalar * Generators::gg())?)?;
            }
            for p in presented {
                bal = (bal + p.ca().clone())?;
            }
            for r in requested {
                bal = (bal + r.ma().negate()?)?;
            }
            statements.push(balance_proof_statement(bal));
        }

        Ok(statements)
    }

    /// Issue MACs and assemble per-credential issuer-parameter Knowledge.
    fn issue_macs<R: WabiSabiRandom>(
        &self,
        requested: &[IssuanceRequest],
        random: &mut R,
    ) -> Result<(Vec<Mac>, Vec<Knowledge>)> {
        let mut macs = Vec::with_capacity(requested.len());
        let mut knowledge = Vec::with_capacity(requested.len());
        for req in requested {
            let t = random.get_scalar();
            let mac = Mac::compute_mac(&self.secret_key, req.ma(), &t)?;
            knowledge.push(issuer_parameters_knowledge(&mac, req.ma(), &self.secret_key)?);
            macs.push(mac);
        }
        Ok((macs, knowledge))
    }

    /// Reset state for tests and cross-round reuse.
    ///
    /// Compiled in for tests and for the `python` feature: the Python
    /// binding needs an explicit way to recycle the issuer between
    /// CoinJoin rounds without rebuilding the whole secret-key + DH
    /// curve setup.
    #[cfg(any(test, feature = "python"))]
    pub fn reset(&self, new_balance: i64) {
        self.balance.store(new_balance, Ordering::SeqCst);
        let mut seen = self.serial_numbers.lock().unwrap();
        seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;
    use crate::wabisabi_client::WabiSabiClient;

    #[test]
    fn test_issuer_creation() {
        let mut random = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut random);
        let issuer = CredentialIssuer::new(sk, 1_000_000).unwrap();
        assert_eq!(issuer.balance(), 1_000_000);
    }

    #[test]
    fn test_issue_zero_credentials() {
        let mut random = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut random);
        let params = sk.compute_parameters().unwrap();
        let issuer = CredentialIssuer::new(sk, 1_000_000).unwrap();
        let client = WabiSabiClient::new(params);

        let (request, validation) = client.create_request_for_zero_amount(&mut random).unwrap();
        let response = issuer.handle_request(&request, &mut random).unwrap();
        let creds = client.handle_response(&response, validation).unwrap();
        assert_eq!(creds.len(), CREDENTIAL_NUMBER);
        for c in &creds {
            assert_eq!(c.value(), 0);
        }
        assert_eq!(issuer.balance(), 1_000_000);
    }
}
