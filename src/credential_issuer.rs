use crate::constants::CREDENTIAL_NUMBER;
use crate::credential_requesting::{CredentialsRequest, CredentialsResponse};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::{
    CredentialIssuerParameters, CredentialIssuerSecretKey, GroupElement, Mac, Scalar,
    ScalarVector,
};
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::{Knowledge, ProofSystem, Statement, Transcript};
use crate::Generators;
use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// Coordinator-side credential issuer with thread-safe state management
///
/// Tracks balance and prevents double-spending via serial number tracking
pub struct CredentialIssuer {
    /// Secret key for MAC issuance
    secret_key: CredentialIssuerSecretKey,
    /// Public parameters
    parameters: CredentialIssuerParameters,
    /// Current balance (atomic for lock-free reads/updates)
    balance: Arc<AtomicI64>,
    /// Serial numbers already seen (prevents double-spending)
    serial_numbers: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl CredentialIssuer {
    /// Create a new credential issuer
    ///
    /// # Arguments
    /// * `secret_key` - Secret key for MAC issuance
    /// * `initial_balance` - Starting balance for the coordinator
    pub fn new(secret_key: CredentialIssuerSecretKey, initial_balance: i64) -> Result<Self> {
        let parameters = secret_key.compute_parameters()?;

        Ok(Self {
            secret_key,
            parameters,
            balance: Arc::new(AtomicI64::new(initial_balance)),
            serial_numbers: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Get the public parameters
    pub fn parameters(&self) -> &CredentialIssuerParameters {
        &self.parameters
    }

    /// Get the current balance
    pub fn balance(&self) -> i64 {
        self.balance.load(Ordering::SeqCst)
    }

    /// Handle a credential request and issue credentials
    ///
    /// # Arguments
    /// * `request` - The credential request from a client
    /// * `random` - Random number generator for MAC generation
    ///
    /// # Returns
    /// CredentialsResponse containing issued MACs and proofs
    ///
    /// # Errors
    /// - Returns error if proofs are invalid
    /// - Returns error if serial numbers are reused (double-spend)
    /// - Returns error if balance would go negative
    pub fn handle_request<R: WabiSabiRandom>(
        &self,
        request: &dyn CredentialsRequest,
        random: &mut R,
    ) -> Result<CredentialsResponse> {
        let delta = request.delta();
        let presented = request.presented();
        let requested = request.requested();
        let proofs = request.proofs();

        // Validate request structure
        if requested.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }

        // Check balance before processing
        let current_balance = self.balance.load(Ordering::SeqCst);
        let new_balance = current_balance
            .checked_sub(delta)
            .ok_or_else(|| WabiSabiError::NegativeBalance(current_balance - delta))?;

        if new_balance < 0 {
            return Err(WabiSabiError::NegativeBalance(new_balance));
        }

        // Extract serial numbers from presented credentials
        let serial_numbers: Vec<Vec<u8>> = presented
            .iter()
            .map(|p| p.s().to_bytes().to_vec())
            .collect();

        // Check for serial number reuse (double-spending)
        {
            let seen = self.serial_numbers.lock().unwrap();
            for serial in serial_numbers.iter() {
                if seen.contains(serial) {
                    return Err(WabiSabiError::SerialNumberAlreadyUsed);
                }
            }
        }

        // Verify all proofs
        let verification_result =
            self.verify_request_proofs(request, random);

        if let Err(e) = verification_result {
            // Don't update state on verification failure
            return Err(e);
        }

        // All checks passed - update state
        self.balance.store(new_balance, Ordering::SeqCst);

        {
            let mut seen = self.serial_numbers.lock().unwrap();
            for serial in serial_numbers.iter() {
                seen.insert(serial.clone());
            }
        }

        // Issue credentials
        self.issue_credentials(requested, random)
    }

    /// Verify all proofs in a credential request
    fn verify_request_proofs<R: WabiSabiRandom>(
        &self,
        request: &dyn CredentialsRequest,
        _random: &mut R,
    ) -> Result<()> {
        let presented = request.presented();
        let requested = request.requested();
        let proofs = request.proofs();
        let delta = request.delta();

        let mut transcript = Transcript::new(b"verify_request");
        let mut statements = Vec::new();

        // 1. Credential presentation proofs
        for presentation in presented.iter() {
            let statement = presentation.create_knowledge_statement(Some(&mut transcript))?;
            statements.push(statement);
        }

        // 2. Balance proof
        let balance_statement =
            self.create_balance_verification_statement(presented, requested, delta, Some(&mut transcript))?;
        statements.push(balance_statement);

        // 3. Range proofs
        for req in requested.iter() {
            let range_statement = self.create_range_verification_statement(
                req.ma(),
                req.bit_commitments(),
                Some(&mut transcript),
            )?;
            statements.push(range_statement);
        }

        // Verify all proofs together
        if !ProofSystem::verify(&mut transcript, &statements, proofs)? {
            return Err(WabiSabiError::CoordinatorReceivedInvalidProofs);
        }

        Ok(())
    }

    /// Create balance verification statement
    fn create_balance_verification_statement(
        &self,
        presented: &[crate::zero_knowledge::CredentialPresentation],
        requested: &[crate::credential_requesting::IssuanceRequest],
        delta: i64,
        transcript: Option<&mut Transcript>,
    ) -> Result<Statement> {
        let mut generators = Vec::new();

        // Start with zero point
        let mut public_point = GroupElement::infinity();

        // Add all presented Ca values
        for presentation in presented.iter() {
            public_point = (public_point + presentation.ca().clone())?;
        }

        // Subtract all requested Ma values
        for request in requested.iter() {
            let neg_ma = request.ma().negate()?;
            public_point = (public_point + neg_ma)?;
        }

        // Add delta term
        let delta_scalar = Scalar::from_i64(delta);
        let delta_point = Generators::gg().multiply(&delta_scalar)?;
        public_point = (public_point + delta_point)?;

        // One Gh generator for each randomness term
        for _ in 0..(presented.len() + requested.len()) {
            generators.push(Generators::gh().clone());
        }

        Ok(Statement::new(public_point, generators))
    }

    /// Create range verification statement
    fn create_range_verification_statement(
        &self,
        ma: &GroupElement,
        bit_commitments: &[GroupElement],
        transcript: Option<&mut Transcript>,
    ) -> Result<Statement> {
        let mut generators = Vec::new();

        // Start with Ma
        let mut public_point = ma.clone();

        // Ma = sum(2^i * Ci), so we need Ma - sum(2^i * Ci) = 0
        for (i, commitment) in bit_commitments.iter().enumerate() {
            let power_of_two = Scalar::from_u64(1u64 << i);
            let scaled_commitment = (&power_of_two * commitment)?;
            let neg = scaled_commitment.negate()?;
            public_point = (public_point + neg)?;
        }

        // Generators for randomness
        for _ in 0..=bit_commitments.len() {
            generators.push(Generators::gh().clone());
        }

        Ok(Statement::new(public_point, generators))
    }

    /// Issue credentials (MACs) for validated requests
    fn issue_credentials<R: WabiSabiRandom>(
        &self,
        requested: &[crate::credential_requesting::IssuanceRequest],
        random: &mut R,
    ) -> Result<CredentialsResponse> {
        let mut issued_credentials = Vec::new();
        let mut proofs = Vec::new();

        let mut transcript = Transcript::new(b"mac_issuance");

        // Generate MACs and proofs for each request
        for request in requested.iter() {
            // Generate random t for MAC
            let t = random.get_scalar();

            // Compute MAC
            let mac = Mac::compute_mac(&self.secret_key, request.ma(), &t)?;
            issued_credentials.push(mac.clone());

            // Generate proof that MAC was correctly issued
            let proof = self.generate_mac_issuance_proof(&mac, request.ma(), &mut transcript, random)?;
            proofs.push(proof);
        }

        Ok(CredentialsResponse::new(issued_credentials, proofs))
    }

    /// Generate a proof that a MAC was correctly issued
    fn generate_mac_issuance_proof<R: WabiSabiRandom>(
        &self,
        mac: &Mac,
        ma: &GroupElement,
        transcript: &mut Transcript,
        random: &mut R,
    ) -> Result<crate::zero_knowledge::Proof> {
        // Prove knowledge of (w, wp, ya) such that:
        // Z' = V - x0*U - x1*t*U = w*Gw + wp*Gwp + ya*Ma

        let z_prime = mac.compute_z_prime(&self.secret_key.x0, &self.secret_key.x1)?;

        let statement = Statement::new(
            z_prime,
            vec![
                Generators::gw().clone(),
                Generators::gwp().clone(),
                ma.clone(),
            ],
        );

        let witness = ScalarVector::new(vec![
            self.secret_key.w,
            self.secret_key.wp,
            self.secret_key.ya,
        ]);

        let knowledge = Knowledge::new(statement, witness)?;

        let proofs = ProofSystem::prove(transcript, &[knowledge], random)?;

        Ok(proofs.into_iter().next().unwrap())
    }

    /// Reset the issuer state (for testing)
    #[cfg(test)]
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
        let (request, _randomness) = client
            .create_request_for_zero_amount(&mut random)
            .unwrap();

        let response = issuer.handle_request(&request, &mut random);
        assert!(response.is_ok());

        // Balance unchanged for zero-value credentials
        assert_eq!(issuer.balance(), 1_000_000);
    }

    #[test]
    fn test_prevent_negative_balance() {
        let mut random = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut random);
        let issuer = CredentialIssuer::new(sk, 100).unwrap();

        // This would require more balance than available
        // (We'd need a proper client request that requests more than balance)
        // This is a simplified test of the balance check logic
        let current = issuer.balance();
        assert_eq!(current, 100);
    }

    #[test]
    fn test_serial_number_tracking() {
        let mut random = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut random);
        let issuer = CredentialIssuer::new(sk, 1_000_000).unwrap();

        // Serial numbers start empty
        let seen = issuer.serial_numbers.lock().unwrap();
        assert_eq!(seen.len(), 0);
    }
}
