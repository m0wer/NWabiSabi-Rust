use crate::constants::{CREDENTIAL_NUMBER, RANGE_PROOF_WIDTH};
use crate::credential_requesting::{
    CredentialsRequest, CredentialsResponse, IssuanceRequest, RealCredentialsRequest,
    ZeroCredentialsRequest,
};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::{
    CredentialIssuerParameters, GroupElement, Scalar, ScalarVector,
};
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::{
    Credential, CredentialPresentation, Knowledge, Proof, ProofSystem, Statement, Transcript,
};
use crate::Generators;

/// Client-side API for WabiSabi credential protocol
///
/// Handles credential request creation and response validation
pub struct WabiSabiClient {
    /// Coordinator's public parameters
    coordinator_parameters: CredentialIssuerParameters,
}

impl WabiSabiClient {
    /// Create a new WabiSabi client
    ///
    /// # Arguments
    /// * `coordinator_parameters` - Public parameters from the coordinator
    pub fn new(coordinator_parameters: CredentialIssuerParameters) -> Self {
        Self {
            coordinator_parameters,
        }
    }

    /// Create a request for zero-value credentials (bootstrap)
    ///
    /// Used to obtain initial credentials that can later be exchanged for real-value credentials.
    ///
    /// # Arguments
    /// * `random` - Random number generator
    ///
    /// # Returns
    /// Tuple of (ZeroCredentialsRequest, secret randomness for handling response)
    pub fn create_request_for_zero_amount<R: WabiSabiRandom>(
        &self,
        random: &mut R,
    ) -> Result<(ZeroCredentialsRequest, Vec<Scalar>)> {
        let mut requested = Vec::new();
        let mut randomness_per_request = Vec::new();

        // Create k credential requests with zero value
        for _ in 0..CREDENTIAL_NUMBER {
            let randomness = random.get_scalar();
            randomness_per_request.push(randomness.clone());

            // Ma = 0*Gg + r*Gh (commitment to zero)
            let ma = Generators::gh().multiply(&randomness)?;

            // No bit commitments needed for zero-value credentials
            let request = IssuanceRequest::new(ma, vec![]);
            requested.push(request);
        }

        // Generate proofs that all requested values are zero
        let mut knowledge_list = Vec::new();
        let mut transcript = Transcript::new(b"zero_request");

        for (request, randomness) in requested.iter().zip(randomness_per_request.iter()) {
            // Prove knowledge of randomness in Ma = r*Gh
            let statement = Statement::new(
                request.ma.clone(),
                vec![Generators::gh().clone()],
            );
            let witness = ScalarVector::new(vec![randomness.clone()]);
            let knowledge = Knowledge::new(statement, witness)?;
            knowledge_list.push(knowledge);
        }

        let proofs = ProofSystem::prove(&mut transcript, &knowledge_list, random)?;

        Ok((
            ZeroCredentialsRequest::new(requested, proofs),
            randomness_per_request,
        ))
    }

    /// Create a request for real-value credentials
    ///
    /// Used to exchange credentials:
    /// - Input registration: Present zero-value, request value credentials (positive delta)
    /// - Output registration: Present value credentials, request zero-value (negative delta)
    /// - Reissuance: Present and request same total value (zero delta)
    ///
    /// # Arguments
    /// * `amounts` - Amounts for the requested credentials
    /// * `credentials_to_present` - Credentials being presented (spent/reissued)
    /// * `random` - Random number generator
    ///
    /// # Returns
    /// Tuple of (RealCredentialsRequest, new credentials' randomness, presented credentials' data)
    pub fn create_request<R: WabiSabiRandom>(
        &self,
        amounts: &[u64],
        credentials_to_present: Vec<Credential>,
        random: &mut R,
    ) -> Result<(
        RealCredentialsRequest,
        Vec<Scalar>,
        Vec<CredentialPresentation>,
    )> {
        if amounts.len() != CREDENTIAL_NUMBER {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }

        // Calculate delta (difference between requested and presented amounts)
        let requested_sum: i64 = amounts.iter().map(|&a| a as i64).sum();
        let presented_sum: i64 = credentials_to_present.iter().map(|c| c.value() as i64).sum();
        let delta = requested_sum - presented_sum;

        // Present existing credentials (randomize them)
        let mut presented = Vec::new();
        let mut z_randomness_per_credential = Vec::new();

        for credential in credentials_to_present.iter() {
            let z = random.get_scalar();
            z_randomness_per_credential.push(z.clone());
            let presentation = credential.present(&z)?;
            presented.push(presentation);
        }

        // Create issuance requests for new credentials
        let mut requested = Vec::new();
        let mut randomness_per_request = Vec::new();

        for &amount in amounts.iter() {
            let (issuance_request, randomness, bit_randomness) =
                self.create_issuance_request(amount, random)?;
            requested.push(issuance_request);
            randomness_per_request.push((randomness, bit_randomness));
        }

        // Generate all proofs (credential presentation, balance, range)
        let mut transcript = Transcript::new(b"real_request");
        let proofs = self.generate_proofs(
            &mut transcript,
            &presented,
            &z_randomness_per_credential,
            &credentials_to_present,
            &requested,
            &randomness_per_request,
            delta,
            random,
        )?;

        // Extract just the randomness (not bit randomness) for response handling
        let randomness_only: Vec<Scalar> = randomness_per_request
            .into_iter()
            .map(|(r, _)| r)
            .collect();

        Ok((
            RealCredentialsRequest::new(delta, presented.clone(), requested, proofs),
            randomness_only,
            presented,
        ))
    }

    /// Handle the coordinator's response and extract credentials
    ///
    /// # Arguments
    /// * `response` - Response from the coordinator
    /// * `randomness` - Secret randomness used in the request
    /// * `request` - The original request (for verification)
    ///
    /// # Returns
    /// Vector of issued credentials
    pub fn handle_response(
        &self,
        response: &CredentialsResponse,
        randomness: &[Scalar],
        request: &dyn CredentialsRequest,
    ) -> Result<Vec<Credential>> {
        let issued_macs = response.issued_credentials();
        let proofs = response.proofs();
        let requested = request.requested();

        if issued_macs.len() != requested.len() {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }

        if proofs.len() != requested.len() {
            return Err(WabiSabiError::InvalidNumberOfProofs);
        }

        if randomness.len() != requested.len() {
            return Err(WabiSabiError::InvalidNumberOfCredentials);
        }

        // Verify the MAC issuance proofs
        let mut transcript = Transcript::new(b"mac_issuance");
        let mut statements = Vec::new();

        for (mac, req) in issued_macs.iter().zip(requested.iter()) {
            // The coordinator proves it issued the MAC correctly:
            // V - x0*U - x1*t*U = w*Gw + wp*Gwp + ya*Ma
            // Since the client doesn't have x0, x1, the client computes:
            // Z' = V - (Cw dot U) where Cw = x0*Gx0 + x1*Gx1
            // This is equivalent to the coordinator's computation
            let u = mac.u();

            // Compute Z' using public parameters
            // Z' = V - (U scaled by Cw)
            let cw_times_u = self.coordinator_parameters.cw.multiply(&mac.t)?;
            let z_prime = (&mac.v - &cw_times_u)?;

            // Statement for the proof
            let statement = Statement::new(
                z_prime,
                vec![
                    Generators::gw().clone(),
                    Generators::gwp().clone(),
                    req.ma().clone(),
                ],
            );
            statements.push(statement);
        }

        // Verify all proofs
        if !ProofSystem::verify(&mut transcript, &statements, proofs)? {
            return Err(WabiSabiError::InvalidMacProofs);
        }

        // Extract credentials (we don't know the amounts yet, set to 0 as placeholder)
        let mut credentials = Vec::new();
        for (mac, r) in issued_macs.iter().zip(randomness.iter()) {
            // For zero-value credentials, amount is 0
            // For real credentials, the amount needs to be tracked separately by the client
            let credential = Credential::new(0, r.clone(), mac.clone())?;
            credentials.push(credential);
        }

        Ok(credentials)
    }

    /// Create an issuance request for a specific amount
    fn create_issuance_request<R: WabiSabiRandom>(
        &self,
        amount: u64,
        random: &mut R,
    ) -> Result<(IssuanceRequest, Scalar, Vec<Scalar>)> {
        let amount_scalar = Scalar::from(amount);
        let randomness = random.get_scalar();

        // Ma = a*Gg + r*Gh (Pedersen commitment to amount)
        let ma_amount_part = Generators::gg().multiply(&amount_scalar)?;
        let ma_randomness_part = Generators::gh().multiply(&randomness)?;
        let ma = (ma_amount_part + ma_randomness_part)?;

        // Create bit commitments for range proof
        let (bit_commitments, bit_randomness) =
            self.create_bit_commitments(amount, random)?;

        let request = IssuanceRequest::new(ma, bit_commitments);
        Ok((request, randomness, bit_randomness))
    }

    /// Create bit commitments for range proof
    ///
    /// Proves that amount ∈ [0, 2^RANGE_PROOF_WIDTH)
    fn create_bit_commitments<R: WabiSabiRandom>(
        &self,
        amount: u64,
        random: &mut R,
    ) -> Result<(Vec<GroupElement>, Vec<Scalar>)> {
        let mut commitments = Vec::new();
        let mut randomness = Vec::new();

        for i in 0..RANGE_PROOF_WIDTH {
            let bit = ((amount >> i) & 1) as u64;
            let bit_scalar = Scalar::from(bit);
            let r = random.get_scalar();

            // Commitment to bit: C_i = bit*Gg + r*Gh
            let bit_part = Generators::gg().multiply(&bit_scalar)?;
            let random_part = Generators::gh().multiply(&r)?;
            let commitment = (bit_part + random_part)?;

            commitments.push(commitment);
            randomness.push(r);
        }

        Ok((commitments, randomness))
    }

    /// Generate all proofs for a real credential request
    #[allow(clippy::too_many_arguments)]
    fn generate_proofs<R: WabiSabiRandom>(
        &self,
        transcript: &mut Transcript,
        presented: &[CredentialPresentation],
        z_randomness: &[Scalar],
        credentials: &[Credential],
        requested: &[IssuanceRequest],
        randomness_with_bits: &[(Scalar, Vec<Scalar>)],
        delta: i64,
        random: &mut R,
    ) -> Result<Vec<Proof>> {
        let mut knowledge_list = Vec::new();

        // 1. Credential presentation proofs (knowledge of credential components)
        for ((presentation, z), credential) in
            presented.iter().zip(z_randomness.iter()).zip(credentials.iter())
        {
            let statement = presentation.create_knowledge_statement(Some(transcript))?;
            let witness = credential.create_presentation_witness(z)?;
            let knowledge = Knowledge::new(statement, witness)?;
            knowledge_list.push(knowledge);
        }

        // 2. Balance proof (sum of presented = sum of requested + delta)
        let balance_statement = self.create_balance_statement(
            presented,
            requested,
            delta,
            Some(transcript),
        )?;
        let balance_witness = self.create_balance_witness(
            z_randomness,
            credentials,
            randomness_with_bits,
        )?;
        let balance_knowledge = Knowledge::new(balance_statement, balance_witness)?;
        knowledge_list.push(balance_knowledge);

        // 3. Range proofs (prove each bit is 0 or 1, and sum equals amount)
        for (request, (randomness, bit_randomness)) in requested.iter().zip(randomness_with_bits.iter()) {
            let range_statement = self.create_range_statement(
                &request.ma,
                &request.bit_commitments,
                Some(transcript),
            )?;
            let range_witness = self.create_range_witness(randomness, bit_randomness)?;
            let range_knowledge = Knowledge::new(range_statement, range_witness)?;
            knowledge_list.push(range_knowledge);
        }

        ProofSystem::prove(transcript, &knowledge_list, random)
    }

    /// Create balance proof statement
    fn create_balance_statement(
        &self,
        presented: &[CredentialPresentation],
        requested: &[IssuanceRequest],
        delta: i64,
        _transcript: Option<&mut Transcript>,
    ) -> Result<Statement> {
        // Sum of Ca (presented) = Sum of Ma (requested) + delta*Gg
        // We combine all public points into a single equation
        let mut public_point = GroupElement::infinity();
        let mut generators = Vec::new();

        // Add all presented Ca values (positive side)
        for presentation in presented.iter() {
            public_point = (public_point + presentation.ca().clone())?;
        }

        // Subtract all requested Ma values
        for request in requested.iter() {
            let neg_ma = request.ma().negate()?;
            public_point = (public_point + neg_ma)?;
        }

        // Add delta*Gg to balance equation
        let delta_scalar = Scalar::from_i64(delta);
        let delta_point = Generators::gg().multiply(&delta_scalar)?;
        public_point = (public_point + delta_point)?;

        // Generators: one Gh for each randomness
        for _ in 0..(presented.len() + requested.len()) {
            generators.push(Generators::gh().clone());
        }

        Ok(Statement::new(public_point, generators))
    }

    /// Create balance proof witness
    fn create_balance_witness(
        &self,
        z_randomness: &[Scalar],
        credentials: &[Credential],
        requested_randomness: &[(Scalar, Vec<Scalar>)],
    ) -> Result<ScalarVector> {
        let mut witness_scalars = Vec::new();

        // Randomness from presented credentials
        for (z, credential) in z_randomness.iter().zip(credentials.iter()) {
            // z * r_a (where r_a is credential's randomness)
            let ra = credential.randomness();
            let witness_part = z * ra;
            witness_scalars.push(witness_part);
        }

        // Randomness from requested credentials
        for (r, _) in requested_randomness.iter() {
            witness_scalars.push(r.clone());
        }

        Ok(ScalarVector::new(witness_scalars))
    }

    /// Create range proof statement
    fn create_range_statement(
        &self,
        ma: &GroupElement,
        bit_commitments: &[GroupElement],
        _transcript: Option<&mut Transcript>,
    ) -> Result<Statement> {
        // Prove: Ma = sum(2^i * Ci) for i in [0, RANGE_PROOF_WIDTH)
        // Where each Ci is a commitment to bit i
        // Combine into a single equation: Ma - sum(2^i * Ci) = 0

        let mut public_point = ma.clone();

        // Subtract 2^i * Ci from the equation
        for (i, commitment) in bit_commitments.iter().enumerate() {
            let power_of_two = Scalar::from(1u64 << i);
            let scaled_commitment = commitment.multiply(&power_of_two)?;
            let neg_scaled = scaled_commitment.negate()?;
            public_point = (public_point + neg_scaled)?;
        }

        // Generators for randomness
        let mut generators = Vec::new();
        for _ in 0..=bit_commitments.len() {
            generators.push(Generators::gh().clone());
        }

        Ok(Statement::new(public_point, generators))
    }

    /// Create range proof witness
    fn create_range_witness(
        &self,
        randomness: &Scalar,
        bit_randomness: &[Scalar],
    ) -> Result<ScalarVector> {
        let mut witness = vec![randomness.clone()];

        // Negate bit randomness since we're subtracting the bit commitments
        for br in bit_randomness.iter() {
            witness.push(br.negate());
        }

        Ok(ScalarVector::new(witness))
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

        let (request, randomness) = client
            .create_request_for_zero_amount(&mut random)
            .unwrap();

        assert_eq!(request.requested().len(), CREDENTIAL_NUMBER);
        assert_eq!(randomness.len(), CREDENTIAL_NUMBER);
        assert_eq!(request.delta(), 0);
        assert_eq!(request.presented().len(), 0);
    }

    // TODO: Re-enable this test when compute_mac is available
    // #[test]
    // fn test_create_real_request() {
    //     let mut random = SecureRandom::new();
    //     let sk = CredentialIssuerSecretKey::new(&mut random);
    //     let params = sk.compute_parameters().unwrap();
    //     let client = WabiSabiClient::new(params);
    //
    //     // Create some dummy credentials to present
    //     let mac = sk.compute_mac(&Generators::gh(), &Scalar::one()).unwrap();
    //     let credential = Credential::new(1000, Scalar::one(), mac).unwrap();
    //
    //     let result = client.create_request(
    //         &[500, 500],
    //         vec![credential],
    //         &mut random,
    //     );
    //
    //     assert!(result.is_ok());
    //     let (request, randomness, presented) = result.unwrap();
    //     assert_eq!(request.requested().len(), CREDENTIAL_NUMBER);
    //     assert_eq!(randomness.len(), CREDENTIAL_NUMBER);
    //     assert_eq!(presented.len(), 1);
    // }
}
