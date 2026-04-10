use crate::crypto::issuer_key::CredentialIssuerSecretKey;
use crate::crypto::{Generators, GroupElement};
use crate::error::Result;
use crate::zero_knowledge::{Statement, Transcript};
use serde::{Deserialize, Serialize};

/// Represents a randomized credential that can be presented to the coordinator
///
/// A randomized credential is a tuple of five group elements: (Ca, Cx0, Cx1, CV, S)
/// These components hide the original credential while still allowing the coordinator
/// to verify it was validly issued.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    /// Randomized amount commitment component: Ca = Ma + z*Ga
    ca: GroupElement,
    /// Randomized MAC's U component: Cx0 = U + z*Gx0
    cx0: GroupElement,
    /// Randomized MAC's (t * U) component: Cx1 = t*U + z*Gx1
    cx1: GroupElement,
    /// Randomized MAC's V component: CV = V + z*GV
    cv: GroupElement,
    /// Credential's randomness hidden behind DL: S = r*Gs (serial number)
    s: GroupElement,
}

impl CredentialPresentation {
    /// Create a new credential presentation
    pub fn new(
        ca: GroupElement,
        cx0: GroupElement,
        cx1: GroupElement,
        cv: GroupElement,
        s: GroupElement,
    ) -> Result<Self> {
        Ok(Self { ca, cx0, cx1, cv, s })
    }

    /// Get the randomized amount commitment
    pub fn ca(&self) -> &GroupElement {
        &self.ca
    }

    /// Get the randomized U component
    pub fn cx0(&self) -> &GroupElement {
        &self.cx0
    }

    /// Get the randomized t*U component
    pub fn cx1(&self) -> &GroupElement {
        &self.cx1
    }

    /// Get the randomized V component
    pub fn cv(&self) -> &GroupElement {
        &self.cv
    }

    /// Get the serial number
    pub fn s(&self) -> &GroupElement {
        &self.s
    }

    /// Compute the Z element needed for proof verification
    ///
    /// Z = CV - (w*Gw + x0*Cx0 + x1*Cx1 + ya*Ca)
    ///
    /// The coordinator uses this to verify that the randomized credential
    /// was properly derived from a valid credential.
    pub fn compute_z(&self, sk: &CredentialIssuerSecretKey) -> Result<GroupElement> {
        // Compute each term
        let term1 = (&sk.w * Generators::gw())?;
        let term2 = (&sk.x0 * &self.cx0)?;
        let term3 = (&sk.x1 * &self.cx1)?;
        let term4 = (&sk.ya * &self.ca)?;

        // Sum all terms
        let sum = (((term1 + term2)? + term3)? + term4)?;

        // Z = CV - sum
        &self.cv - &sum
    }

    /// Create a knowledge statement for this credential presentation
    /// This is used for zero-knowledge proof generation/verification
    pub fn create_knowledge_statement(
        &self,
        transcript: Option<&mut Transcript>,
    ) -> Result<Statement> {
        // For now, return a placeholder error
        // A full implementation would construct the appropriate Statement
        // for proving knowledge of the credential
        Err(crate::error::WabiSabiError::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};
    use crate::crypto::{Mac, Scalar};
    use crate::zero_knowledge::Credential;

    #[test]
    fn test_presentation_creation() {
        let ca = GroupElement::infinity();
        let cx0 = GroupElement::infinity();
        let cx1 = GroupElement::infinity();
        let cv = GroupElement::infinity();
        let s = GroupElement::infinity();

        let presentation = CredentialPresentation::new(ca, cx0, cx1, cv, s).unwrap();

        assert!(presentation.ca().is_infinity());
    }

    #[test]
    fn test_compute_z() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        // Create a credential
        let value = 10_000i64;
        let randomness = rng.get_scalar();

        let value_scalar = Scalar::from_bytes(&{
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(value as u64).to_le_bytes());
            bytes
        })
        .unwrap();

        let ma = ((value_scalar * Generators::gg()).unwrap()
            + (randomness * Generators::gh()).unwrap())
        .unwrap();

        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

        let credential = Credential::new(value, randomness, mac).unwrap();

        // Present the credential
        let z = rng.get_scalar();
        let presentation = credential.present(&z).unwrap();

        // Compute Z
        let capital_z = presentation.compute_z(&sk).unwrap();

        // Z should equal z * I (where I = ya*Ga)
        let params = sk.compute_parameters().unwrap();
        let expected_z = (&z * &params.i).unwrap();

        assert_eq!(capital_z, expected_z);
    }

    #[test]
    fn test_different_randomization_different_presentation() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        let value = 25_000i64;
        let randomness = rng.get_scalar();

        let value_scalar = Scalar::from_bytes(&{
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(value as u64).to_le_bytes());
            bytes
        })
        .unwrap();

        let ma = ((value_scalar * Generators::gg()).unwrap()
            + (randomness * Generators::gh()).unwrap())
        .unwrap();

        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

        let credential = Credential::new(value, randomness, mac).unwrap();

        // Present with two different randomization factors
        let z1 = rng.get_scalar();
        let z2 = rng.get_scalar();

        let presentation1 = credential.present(&z1).unwrap();
        let presentation2 = credential.present(&z2).unwrap();

        // Different randomizations should produce different presentations
        assert_ne!(presentation1.ca(), presentation2.ca());
        assert_ne!(presentation1.cx0(), presentation2.cx0());
        assert_ne!(presentation1.cx1(), presentation2.cx1());
        assert_ne!(presentation1.cv(), presentation2.cv());

        // Serial number should be the same (deterministic)
        assert_eq!(presentation1.s(), presentation2.s());
    }
}
