use crate::constants::WABISABI_PROTOCOL_IDENTIFIER;
use crate::crypto::{GroupElement, Scalar};
use crate::crypto::randomness::WabiSabiRandom;
use crate::error::Result;
use crate::zero_knowledge::SyntheticSecretNonceProvider;
use strobe_rs::{SecParam, Strobe};

/// High-level API for transcripts of compound Sigma protocol style proofs
/// Implements synthetic nonces and Fiat-Shamir challenges using Strobe128
pub struct Transcript {
    strobe: Strobe,
}

impl Transcript {
    const KEY_SIZE_IN_BYTES: usize = 32;

    // Tags for domain separation
    const STATEMENT_TAG: &'static [u8] = b"statement";
    const CHALLENGE_TAG: &'static [u8] = b"challenge";
    const PUBLIC_NONCE_TAG: &'static [u8] = b"nonce-commitment";
    const DOMAIN_SEPARATOR_TAG: &'static [u8] = b"domain-separator";

    /// Initialize a new transcript with the supplied label, which is used as a domain separator
    ///
    /// This function should be called by a proof library's API consumer (i.e., the application
    /// using the proof library), and **not by the proof implementation**.
    pub fn new(label: &[u8]) -> Self {
        let strobe = Strobe::new(WABISABI_PROTOCOL_IDENTIFIER.as_bytes(), SecParam::B128);
        let mut transcript = Self { strobe };
        transcript.add_message(Self::DOMAIN_SEPARATOR_TAG, label);
        transcript
    }

    /// Generate synthetic nonce provider using current state combined with additional randomness
    pub fn create_synthetic_secret_nonce_provider<R: WabiSabiRandom>(
        &self,
        secrets: &[Scalar],
        random: &mut R,
    ) -> SyntheticSecretNonceProvider {
        SyntheticSecretNonceProvider::new(self.strobe.clone(), secrets, random)
    }

    /// Commit public nonces to the transcript
    pub fn commit_public_nonces(&mut self, public_nonces: &[GroupElement]) {
        let nonce_bytes: Vec<[u8; 33]> = public_nonces
            .iter()
            .map(|ge| ge.to_bytes())
            .collect();
        self.add_messages(Self::PUBLIC_NONCE_TAG, &nonce_bytes);
    }

    /// Commit a statement to the transcript
    pub fn commit_statement(
        &mut self,
        public_points: &[GroupElement],
        generators: &[GroupElement],
    ) {
        let mut all_points = Vec::new();
        all_points.extend(public_points.iter().map(|ge| ge.to_bytes()));
        all_points.extend(generators.iter().map(|ge| ge.to_bytes()));
        self.add_messages(Self::STATEMENT_TAG, &all_points);
    }

    /// Generate a Fiat-Shamir challenge
    pub fn generate_challenge(&mut self) -> Result<Scalar> {
        loop {
            self.strobe.ad(Self::CHALLENGE_TAG, false);
            let mut challenge_bytes = [0u8; Self::KEY_SIZE_IN_BYTES];
            self.strobe.prf(&mut challenge_bytes, false);

            // Try to create a valid scalar, retry if it overflows the field
            if let Ok(scalar) = Scalar::from_bytes(&challenge_bytes) {
                if !scalar.is_zero() {
                    return Ok(scalar);
                }
            }
        }
    }

    /// Add a single message with label
    fn add_message(&mut self, label: &[u8], message: &[u8]) {
        self.strobe.ad(label, false);
        let len_bytes = (message.len() as u32).to_le_bytes();
        self.strobe.ad(&len_bytes, true);
        self.strobe.ad(message, false);
    }

    /// Add multiple messages with label
    fn add_messages<const N: usize>(&mut self, label: &[u8], messages: &[[u8; N]]) {
        self.strobe.ad(label, false);
        let count_bytes = (messages.len() as u32).to_le_bytes();
        self.strobe.ad(&count_bytes, true);

        for (index, message) in messages.iter().enumerate() {
            let index_bytes = (index as u32).to_le_bytes();
            self.add_message(&index_bytes, message);
        }
    }

    /// Clone the internal Strobe state (for nonce provider)
    pub(crate) fn clone_strobe(&self) -> Strobe {
        self.strobe.clone()
    }
}

impl Clone for Transcript {
    fn clone(&self) -> Self {
        Self {
            strobe: self.strobe.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;

    #[test]
    fn test_transcript_creation() {
        let transcript = Transcript::new(b"test-protocol");
        // Should not panic
    }

    #[test]
    fn test_challenge_generation() {
        let mut transcript = Transcript::new(b"test-protocol");
        let challenge1 = transcript.generate_challenge().unwrap();
        let challenge2 = transcript.generate_challenge().unwrap();
        // Challenges should be different
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_deterministic_transcript() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        let c1 = t1.generate_challenge().unwrap();
        let c2 = t2.generate_challenge().unwrap();

        // Same inputs should produce same challenge
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_nonce_commitment() {
        let mut transcript = Transcript::new(b"test");
        let nonces = vec![GroupElement::infinity()];
        transcript.commit_public_nonces(&nonces);
        // Should not panic
    }
}
