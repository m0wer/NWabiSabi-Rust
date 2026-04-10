use crate::crypto::{Generators, GroupElement, Mac, Scalar};
use crate::error::{Result, WabiSabiError};
use crate::zero_knowledge::CredentialPresentation;
use serde::{Deserialize, Serialize};

/// Represents an anonymous credential and its represented data
///
/// A credential consists of:
/// - An amount (value)
/// - Randomness used for Pedersen commitment blinding
/// - An algebraic MAC proving the credential was issued by the coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Amount represented by the credential (in satoshis or similar units)
    value: i64,
    /// Randomness used as blinding factor for the Pedersen committed amount
    randomness: Scalar,
    /// Algebraic MAC representing the anonymous credential issued by the coordinator
    mac: Mac,
}

impl Credential {
    /// Create a new credential
    pub fn new(value: i64, randomness: Scalar, mac: Mac) -> Result<Self> {
        if value < 0 {
            return Err(WabiSabiError::Unspecified);
        }

        Ok(Self {
            value,
            randomness,
            mac,
        })
    }

    /// Get the amount represented by the credential
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Get the randomness used in the Pedersen commitment
    pub fn randomness(&self) -> &Scalar {
        &self.randomness
    }

    /// Get the MAC
    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    /// Randomize the credential for presentation to the coordinator
    ///
    /// This creates a CredentialPresentation that hides the link between
    /// the original credential and the presented one, providing anonymity.
    ///
    /// The randomization uses a scalar z to randomize all components:
    /// - Ca = Ma + z*Ga (randomized amount commitment)
    /// - Cx0 = U + z*Gx0 (randomized MAC U component)
    /// - Cx1 = t*U + z*Gx1 (randomized MAC t*U component)
    /// - CV = V + z*GV (randomized MAC V component)
    /// - S = r*Gs (serial number, prevents double-spending)
    pub fn present(&self, z: &Scalar) -> Result<CredentialPresentation> {
        // Helper function to randomize: M' = M + z*G
        let randomize = |g: &GroupElement, m: &GroupElement| -> Result<GroupElement> {
            let z_times_g = (z * g)?;
            m.clone() + z_times_g
        };

        // Compute Ma = value*Gg + randomness*Gh (Pedersen commitment)
        let value_scalar = self.value_as_scalar()?;
        let ma = self.pedersen_commitment(&value_scalar, &self.randomness)?;

        // Randomize all components
        let ca = randomize(Generators::ga(), &ma)?;
        let cx0 = randomize(Generators::gx0(), &self.mac.u())?;

        let t_times_u = (&self.mac.t * &self.mac.u())?;
        let cx1 = randomize(Generators::gx1(), &t_times_u)?;

        let cv = randomize(Generators::gv(), &self.mac.v)?;

        // Serial number S = r*Gs
        let s = (&self.randomness * Generators::gs())?;

        CredentialPresentation::new(ca, cx0, cx1, cv, s)
    }

    /// Convert the credential value to a Scalar
    fn value_as_scalar(&self) -> Result<Scalar> {
        if self.value < 0 {
            return Err(WabiSabiError::Unspecified);
        }

        // Convert i64 to u64 (safe because we checked it's non-negative)
        let value_u64 = self.value as u64;

        // Convert to 32-byte array (little-endian)
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value_u64.to_le_bytes());

        Scalar::from_bytes(&bytes)
    }

    /// Compute Pedersen commitment: value*Gg + randomness*Gh
    fn pedersen_commitment(&self, value: &Scalar, randomness: &Scalar) -> Result<GroupElement> {
        let value_term = (value * Generators::gg())?;
        let randomness_term = (randomness * Generators::gh())?;
        value_term + randomness_term
    }

    /// Create the witness for a credential presentation proof
    ///
    /// The witness includes the secret values known to the credential holder
    pub fn create_presentation_witness(&self, z: &Scalar) -> Result<crate::crypto::ScalarVector> {
        // The witness for credential presentation includes:
        // - value
        // - randomness (r_a)
        // - z (randomization factor)
        // - t (MAC component)
        let value_scalar = self.value_as_scalar()?;
        Ok(crate::crypto::ScalarVector::new(vec![
            value_scalar,
            self.randomness.clone(),
            z.clone(),
            self.mac.t.clone(),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::issuer_key::CredentialIssuerSecretKey;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};

    #[test]
    fn test_credential_creation() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        let value = 10_000i64;
        let randomness = rng.get_scalar();

        // Create attribute Ma
        let value_scalar = Scalar::from_bytes(&{
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(value as u64).to_le_bytes());
            bytes
        })
        .unwrap();
        let ma = ((value_scalar * Generators::gg()).unwrap()
            + (randomness * Generators::gh()).unwrap())
        .unwrap();

        // Generate MAC
        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

        let credential = Credential::new(value, randomness, mac).unwrap();

        assert_eq!(credential.value(), 10_000);
    }

    #[test]
    fn test_credential_presentation() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        let value = 50_000i64;
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

        // Randomize for presentation
        let z = rng.get_scalar();
        let presentation = credential.present(&z).unwrap();

        // Presentation should have all components
        assert!(!presentation.ca().is_infinity());
        assert!(!presentation.cx0().is_infinity());
        assert!(!presentation.cx1().is_infinity());
        assert!(!presentation.cv().is_infinity());
        assert!(!presentation.s().is_infinity());
    }

    #[test]
    fn test_negative_value_rejected() {
        let mut rng = SecureRandom::new();
        let randomness = rng.get_scalar();
        let t = rng.get_scalar();
        let v = GroupElement::infinity();
        let mac = Mac::new(t, v).unwrap();

        let result = Credential::new(-1000, randomness, mac);
        assert!(result.is_err());
    }
}
