use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::GroupElementVector;
use crate::error::Result;
use crate::zero_knowledge::linear_relation::{Knowledge, Statement};
use crate::zero_knowledge::{Proof, Transcript};

/// Zero-knowledge proof system using Sigma protocols
pub struct ProofSystem;

impl ProofSystem {
    /// Generate proofs for multiple pieces of knowledge
    ///
    /// This implements the Fiat-Shamir transformed Sigma protocol:
    /// 1. Commit to statements
    /// 2. Generate synthetic secret nonces
    /// 3. Commit to public nonces
    /// 4. Generate challenge via Fiat-Shamir
    /// 5. Compute responses
    pub fn prove<R: WabiSabiRandom>(
        transcript: &mut Transcript,
        knowledge: &[Knowledge],
        random: &mut R,
    ) -> Result<Vec<Proof>> {
        // Step 1: Commit all statements to the transcript
        for k in knowledge {
            let public_points: Vec<_> = k.statement.public_points().iter().map(|p| (*p).clone()).collect();
            let generators: Vec<_> = k.statement.generators().iter().map(|g| (*g).clone()).collect();
            transcript.commit_statement(&public_points, &generators);
        }

        // Step 2 & 3: Generate secret nonces and compute public nonces
        let mut deferred_proofs = Vec::new();

        for k in knowledge {
            // Generate synthetic secret nonces (combines witness with randomness)
            let mut secret_nonce_provider = transcript.create_synthetic_secret_nonce_provider(
                k.witness.as_slice(),
                random,
            );
            let secret_nonces = secret_nonce_provider.get_scalar_vector()?;

            // Compute public nonces: R_i = k_i * G_i for each equation
            let mut public_nonces = Vec::new();
            for equation in &k.statement.equations {
                let nonce = (&secret_nonces * &equation.generators)?;
                public_nonces.push(nonce);
            }
            let public_nonces_vec = GroupElementVector::new(public_nonces);

            // Commit public nonces to transcript
            transcript.commit_public_nonces(public_nonces_vec.as_slice());

            // Store data needed to create proof after challenge is generated
            deferred_proofs.push((public_nonces_vec, k, secret_nonces));
        }

        // Step 4: Generate Fiat-Shamir challenge
        let challenge = transcript.generate_challenge()?;

        // Step 5: Compute responses for each proof
        let mut proofs = Vec::new();
        for (public_nonces, k, secret_nonces) in deferred_proofs {
            let responses = k.respond_to_challenge(&challenge, &secret_nonces)?;
            proofs.push(Proof::new(public_nonces, responses));
        }

        Ok(proofs)
    }

    /// Verify proofs for multiple statements
    ///
    /// Verification follows the same Fiat-Shamir structure:
    /// 1. Commit to statements (same as prover)
    /// 2. Commit to public nonces from proofs
    /// 3. Generate challenge (should match prover's challenge)
    /// 4. Verify each equation
    pub fn verify(
        transcript: &mut Transcript,
        statements: &[Statement],
        proofs: &[Proof],
    ) -> Result<bool> {
        // Check that number of proofs matches number of statements
        if statements.len() != proofs.len() {
            return Ok(false);
        }

        // Step 1: Commit all statements to the transcript
        for statement in statements {
            let public_points: Vec<_> = statement.public_points().iter().map(|p| (*p).clone()).collect();
            let generators: Vec<_> = statement.generators().iter().map(|g| (*g).clone()).collect();
            transcript.commit_statement(&public_points, &generators);
        }

        // Step 2: Commit all public nonces to the transcript
        for proof in proofs {
            transcript.commit_public_nonces(proof.public_nonces.as_slice());
        }

        // Step 3: Generate Fiat-Shamir challenge (must match prover's)
        let challenge = transcript.generate_challenge()?;

        // Step 4: Verify each statement with its proof
        for (statement, proof) in statements.iter().zip(proofs.iter()) {
            if !statement.check_verification_equation(
                &proof.public_nonces,
                &challenge,
                &proof.responses,
            )? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;
    use crate::crypto::{Generators, ScalarVector};

    #[test]
    fn test_simple_proof() {
        let mut rng = SecureRandom::new();

        // Create a simple statement: P = x*G
        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let witness = ScalarVector::new(vec![x]);
        let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

        // Generate proof
        let mut transcript = Transcript::new(b"test protocol");
        let proofs = ProofSystem::prove(&mut transcript, &[knowledge], &mut rng).unwrap();

        assert_eq!(proofs.len(), 1);

        // Verify proof
        let mut transcript = Transcript::new(b"test protocol");
        let valid = ProofSystem::verify(&mut transcript, &[statement], &proofs).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_multi_knowledge_proof() {
        let mut rng = SecureRandom::new();

        // Create two statements
        let g = Generators::g().clone();
        let h = Generators::gh().clone();

        let x1 = rng.get_scalar();
        let p1 = (&x1 * &g).unwrap();
        let statement1 = Statement::new(p1, vec![g.clone()]);
        let witness1 = ScalarVector::new(vec![x1]);
        let knowledge1 = Knowledge::new(statement1.clone(), witness1).unwrap();

        let x2 = rng.get_scalar();
        let p2 = (&x2 * &h).unwrap();
        let statement2 = Statement::new(p2, vec![h]);
        let witness2 = ScalarVector::new(vec![x2]);
        let knowledge2 = Knowledge::new(statement2.clone(), witness2).unwrap();

        // Generate proofs
        let mut transcript = Transcript::new(b"test protocol");
        let proofs = ProofSystem::prove(&mut transcript, &[knowledge1, knowledge2], &mut rng).unwrap();

        assert_eq!(proofs.len(), 2);

        // Verify proofs
        let mut transcript = Transcript::new(b"test protocol");
        let valid = ProofSystem::verify(&mut transcript, &[statement1, statement2], &proofs).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_invalid_proof_fails_verification() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let witness = ScalarVector::new(vec![x]);
        let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

        // Generate proof
        let mut transcript = Transcript::new(b"test protocol");
        let mut proofs = ProofSystem::prove(&mut transcript, &[knowledge], &mut rng).unwrap();

        // Tamper with the proof
        let tampered_response = rng.get_scalar();
        proofs[0].responses = ScalarVector::new(vec![tampered_response]);

        // Verify should fail
        let mut transcript = Transcript::new(b"test protocol");
        let valid = ProofSystem::verify(&mut transcript, &[statement], &proofs).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_wrong_protocol_fails_verification() {
        let mut rng = SecureRandom::new();

        let g = Generators::g().clone();
        let x = rng.get_scalar();
        let p = (&x * &g).unwrap();

        let statement = Statement::new(p, vec![g]);
        let witness = ScalarVector::new(vec![x]);
        let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

        // Generate proof with one protocol label
        let mut transcript = Transcript::new(b"protocol1");
        let proofs = ProofSystem::prove(&mut transcript, &[knowledge], &mut rng).unwrap();

        // Try to verify with different protocol label
        let mut transcript = Transcript::new(b"protocol2");
        let valid = ProofSystem::verify(&mut transcript, &[statement], &proofs).unwrap();

        assert!(!valid);
    }
}
