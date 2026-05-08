//! Stand-alone show of a credential whose amount is publicly revealed.
//!
//! This is the JMP-0005 ZK-4 (`!zkpreg`) building block: a maker proves
//! that a fresh CoinJoin output (address, amount, output_type) was
//! authorized by a previously issued credential, without re-blinding
//! that credential through the issuer.
//!
//! Compared to the issuer-side show used inside a credentials request,
//! this presentation:
//!
//! 1. publicly reveals the amount (which the on-chain output exposes
//!    anyway), reducing the witness to width 4;
//! 2. carries `z_public = z*I` alongside the presentation, so the
//!    verifier can recompute it from the secret key (`Z' = compute_z(sk)`)
//!    and reject any presentation whose underlying MAC was not issued by
//!    this coordinator;
//! 3. is bound to a caller-supplied transcript label, which downstream
//!    protocols use to bind the proof to (epoch_id, address,
//!    output_type, amount) so the show is non-malleable across outputs.

use serde::{Deserialize, Serialize};

use crate::crypto::issuer_key::{CredentialIssuerParameters, CredentialIssuerSecretKey};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::GroupElement;
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::statements::{
    show_credential_revealed_amount_knowledge, show_credential_revealed_amount_statement,
};
use crate::zero_knowledge::{Credential, CredentialPresentation, Proof, ProofSystem, Transcript};

/// Stand-alone "show this credential is worth `amount`" blob.
///
/// Bincode-encoded by callers; the struct itself is transport-agnostic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationShow {
    /// Rerandomized credential `(Ca, Cx0, Cx1, Cv, S)`.
    pub presentation: CredentialPresentation,
    /// Public point `z * I` produced by the prover. The verifier
    /// cross-checks this against `presentation.compute_z(sk)`; equality
    /// is what binds the show to *this* issuer's MAC.
    pub z_public: GroupElement,
    /// Sigma proof over the revealed-amount statement.
    pub proof: Proof,
}

impl RegistrationShow {
    /// Produce a fresh registration show for `credential`.
    ///
    /// `transcript_label` should encode every output-bound field the
    /// caller wants to make non-malleable (epoch id, address, amount,
    /// output type).
    pub fn prove<R: WabiSabiRandom>(
        credential: &Credential,
        iparams: &CredentialIssuerParameters,
        transcript_label: &[u8],
        random: &mut R,
    ) -> Result<Self> {
        if credential.value() < 0 {
            return Err(WabiSabiError::Unspecified);
        }
        let z = random.get_scalar();
        let presentation = credential.present(&z)?;
        let z_public = (&z * &iparams.i)?;
        let knowledge = show_credential_revealed_amount_knowledge(
            &presentation,
            &z,
            credential.value(),
            credential.randomness(),
            &credential.mac().t,
            iparams,
        )?;
        let mut transcript = Transcript::new(transcript_label);
        let mut proofs =
            ProofSystem::prove(&mut transcript, std::slice::from_ref(&knowledge), random)?;
        let proof = proofs.pop().ok_or(WabiSabiError::Unspecified)?;
        Ok(Self {
            presentation,
            z_public,
            proof,
        })
    }

    /// Verify the show against `(amount, transcript_label)` and return
    /// the credential's serial number `S = r*Gs` in 33-byte compressed
    /// form on success.
    ///
    /// The verifier recomputes `Z' = compute_z(sk)` from the secret key
    /// and rejects the show unless `Z' == z_public`. That equality is
    /// what proves the underlying MAC was issued by this coordinator
    /// (the Sigma proof on its own only proves knowledge of `z` such
    /// that `Z = z*I`, which any prover can fabricate).
    pub fn verify(
        &self,
        amount: i64,
        sk: &CredentialIssuerSecretKey,
        iparams: &CredentialIssuerParameters,
        transcript_label: &[u8],
    ) -> Result<[u8; 33]> {
        if amount < 0 {
            return Err(WabiSabiError::Unspecified);
        }
        let z_recomputed = self.presentation.compute_z(sk)?;
        if z_recomputed != self.z_public {
            return Err(WabiSabiError::Unspecified);
        }
        let statement = show_credential_revealed_amount_statement(
            &self.presentation,
            &self.z_public,
            amount,
            iparams,
        )?;
        let mut transcript = Transcript::new(transcript_label);
        let ok = ProofSystem::verify(
            &mut transcript,
            std::slice::from_ref(&statement),
            std::slice::from_ref(&self.proof),
        )?;
        if !ok {
            return Err(WabiSabiError::Unspecified);
        }
        Ok(self.presentation.s().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::issuer_key::CredentialIssuerSecretKey;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::{Generators, Mac, Scalar};

    fn fresh_rng() -> SecureRandom {
        SecureRandom::new()
    }

    fn issue_credential(
        sk: &CredentialIssuerSecretKey,
        value: i64,
        rng: &mut SecureRandom,
    ) -> (Credential, CredentialIssuerParameters) {
        let randomness = rng.get_scalar();
        let value_scalar = Scalar::from_u64(value as u64);
        let ma = ((value_scalar * Generators::gg()).unwrap()
            + (&randomness * Generators::gh()).unwrap())
        .unwrap();
        let t = rng.get_scalar();
        let mac = Mac::compute_mac(sk, &ma, &t).unwrap();
        let cred = Credential::new(value, randomness, mac).unwrap();
        let params = sk.compute_parameters().unwrap();
        (cred, params)
    }

    #[test]
    fn registration_show_roundtrip() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let amount = 33_000i64;
        let (cred, params) = issue_credential(&sk, amount, &mut rng);

        let label = b"jmp-zkpreg|epoch=abc|out=0";
        let show = RegistrationShow::prove(&cred, &params, label, &mut rng).unwrap();
        let serial = show.verify(amount, &sk, &params, label).unwrap();
        assert_eq!(serial.len(), 33);
        // Serial determinism: a second show of the same credential
        // produces the same S (S = r*Gs is deterministic in r).
        let show2 = RegistrationShow::prove(&cred, &params, label, &mut rng).unwrap();
        let serial2 = show2.verify(amount, &sk, &params, label).unwrap();
        assert_eq!(serial, serial2);
    }

    #[test]
    fn registration_show_wrong_amount_rejected() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let (cred, params) = issue_credential(&sk, 21_000, &mut rng);
        let label = b"jmp-zkpreg|epoch=xyz";
        let show = RegistrationShow::prove(&cred, &params, label, &mut rng).unwrap();
        assert!(show.verify(20_999, &sk, &params, label).is_err());
        assert!(show.verify(21_001, &sk, &params, label).is_err());
    }

    #[test]
    fn registration_show_wrong_label_rejected() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let (cred, params) = issue_credential(&sk, 5_000, &mut rng);
        let show = RegistrationShow::prove(&cred, &params, b"label-A", &mut rng).unwrap();
        assert!(show.verify(5_000, &sk, &params, b"label-B").is_err());
    }

    #[test]
    fn registration_show_wrong_issuer_rejected() {
        let mut rng = fresh_rng();
        let sk_real = CredentialIssuerSecretKey::new(&mut rng);
        let sk_other = CredentialIssuerSecretKey::new(&mut rng);
        let (cred, params_real) = issue_credential(&sk_real, 9_000, &mut rng);
        let label = b"jmp-zkpreg";
        let show = RegistrationShow::prove(&cred, &params_real, label, &mut rng).unwrap();
        // Foreign issuer's secret key recomputes a different Z'.
        let params_other = sk_other.compute_parameters().unwrap();
        assert!(show.verify(9_000, &sk_other, &params_other, label).is_err());
    }

    #[test]
    fn registration_show_z_public_tampering_rejected() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let (cred, params) = issue_credential(&sk, 1_500, &mut rng);
        let label = b"jmp-zkpreg";
        let mut show = RegistrationShow::prove(&cred, &params, label, &mut rng).unwrap();
        // Replace z_public with an unrelated point. The compute_z check
        // catches this before the Sigma proof verification.
        show.z_public = (&rng.get_scalar() * &params.i).unwrap();
        assert!(show.verify(1_500, &sk, &params, label).is_err());
    }

    #[test]
    fn registration_show_zero_amount_roundtrip() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let (cred, params) = issue_credential(&sk, 0, &mut rng);
        let label = b"jmp-zkpreg|change=0";
        let show = RegistrationShow::prove(&cred, &params, label, &mut rng).unwrap();
        let _serial = show.verify(0, &sk, &params, label).unwrap();
    }
}
