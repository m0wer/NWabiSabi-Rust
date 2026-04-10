use crate::crypto::issuer_key::CredentialIssuerSecretKey;
use crate::crypto::{generators, GroupElement, Scalar};
use crate::error::{Result, WabiSabiError};
use serde::{Deserialize, Serialize};

/// Message Authentication Code (MAC) over group elements
///
/// An algebraic MAC that allows proving knowledge of a credential without revealing it.
/// The MAC is computed as: V = (x0 + x1*t)*U(t) + M
/// where U(t) is a deterministic hash-to-curve function of t.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mac {
    /// Random scalar t
    pub t: Scalar,
    /// MAC value V = (x0 + x1*t)*U(t) + M
    pub v: GroupElement,
}

impl Mac {
    /// Create a new MAC (internal constructor - use compute_mac instead)
    pub(crate) fn new(t: Scalar, v: GroupElement) -> Result<Self> {
        if t.is_zero() {
            return Err(WabiSabiError::Unspecified);
        }
        if v.is_infinity() {
            return Err(WabiSabiError::Unspecified);
        }

        Ok(Self { t, v })
    }

    /// Compute a MAC for a message using the issuer's secret key
    ///
    /// Formula: V = (x0 + x1*t)*U(t) + M
    /// where M = w*Gw + ya*Ma
    pub fn compute_mac(
        sk: &CredentialIssuerSecretKey,
        ma: &GroupElement,
        t: &Scalar,
    ) -> Result<Self> {
        if t.is_zero() {
            return Err(WabiSabiError::Unspecified);
        }
        if ma.is_infinity() {
            return Err(WabiSabiError::Unspecified);
        }

        // M = w*Gw + ya*Ma
        let m_part1 = (&sk.w * crate::crypto::Generators::gw())?;
        let m_part2 = (&sk.ya * ma)?;
        let m = (m_part1 + m_part2)?;

        Self::compute_algebraic_mac(&sk.x0, &sk.x1, &m, t)
    }

    /// Verify that this MAC is valid for the given message and secret key
    pub fn verify_mac(&self, sk: &CredentialIssuerSecretKey, ma: &GroupElement) -> Result<bool> {
        let recomputed = Self::compute_mac(sk, ma, &self.t)?;
        Ok(recomputed == *self)
    }

    /// Get U(t) = hash-to-curve(t)
    pub fn u(&self) -> GroupElement {
        Self::generate_u(&self.t)
    }

    /// Compute Z' = V - x0*U - x1*t*U
    /// This is used in credential presentation verification
    ///
    /// Formula: Z' = V - (x0 + x1*t)*U(t) = w*Gw + wp*Gwp + ya*Ma
    ///
    /// Note: This method requires the secret key (x0, x1) to compute Z'.
    /// It should be called from CredentialIssuer which has access to the secret key.
    pub fn compute_z_prime(
        &self,
        x0: &Scalar,
        x1: &Scalar,
    ) -> Result<GroupElement> {
        // Compute (x0 + x1*t)
        let coeff = *x0 + (*x1 * self.t);

        // Compute U(t)
        let u = self.u();

        // Compute (x0 + x1*t)*U(t)
        let coeff_times_u = (&coeff * &u)?;

        // Compute Z' = V - (x0 + x1*t)*U(t)
        &self.v - &coeff_times_u
    }

    /// Generate U(t) deterministically from t using hash-to-curve
    pub fn generate_u(t: &Scalar) -> GroupElement {
        let t_bytes = t.to_bytes();
        generators::from_bytes(&t_bytes)
    }

    /// Compute the algebraic MAC: V = (x0 + x1*t)*U(t) + M
    fn compute_algebraic_mac(
        x0: &Scalar,
        x1: &Scalar,
        m: &GroupElement,
        t: &Scalar,
    ) -> Result<Self> {
        // Compute (x0 + x1*t)
        let coeff = *x0 + (*x1 * *t);

        // Compute U(t)
        let u = Self::generate_u(t);

        // Compute (x0 + x1*t)*U(t)
        let coeff_times_u = (&coeff * &u)?;

        // Compute V = (x0 + x1*t)*U(t) + M
        let v = (coeff_times_u + m.clone())?;

        Self::new(*t, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::{SecureRandom, WabiSabiRandom};

    #[test]
    fn test_mac_computation() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        // Create an attribute Ma
        let ma_scalar = rng.get_scalar();
        let ma = (&ma_scalar * crate::crypto::Generators::ga()).unwrap();

        // Generate a MAC
        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

        assert!(!mac.t.is_zero());
        assert!(!mac.v.is_infinity());
    }

    #[test]
    fn test_mac_verification() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        let ma_scalar = rng.get_scalar();
        let ma = (&ma_scalar * crate::crypto::Generators::ga()).unwrap();

        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

        // Verification should succeed
        assert!(mac.verify_mac(&sk, &ma).unwrap());
    }

    #[test]
    fn test_mac_verification_fails_wrong_key() {
        let mut rng = SecureRandom::new();
        let sk1 = CredentialIssuerSecretKey::new(&mut rng);
        let sk2 = CredentialIssuerSecretKey::new(&mut rng);

        let ma_scalar = rng.get_scalar();
        let ma = (&ma_scalar * crate::crypto::Generators::ga()).unwrap();

        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk1, &ma, &t).unwrap();

        // Verification with different key should fail
        assert!(!mac.verify_mac(&sk2, &ma).unwrap());
    }

    #[test]
    fn test_mac_verification_fails_wrong_ma() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);

        let ma1_scalar = rng.get_scalar();
        let ma1 = (&ma1_scalar * crate::crypto::Generators::ga()).unwrap();

        let ma2_scalar = rng.get_scalar();
        let ma2 = (&ma2_scalar * crate::crypto::Generators::ga()).unwrap();

        let t = rng.get_scalar();
        let mac = Mac::compute_mac(&sk, &ma1, &t).unwrap();

        // Verification with different Ma should fail
        assert!(!mac.verify_mac(&sk, &ma2).unwrap());
    }

    #[test]
    fn test_generate_u_deterministic() {
        let t = Scalar::one();

        let u1 = Mac::generate_u(&t);
        let u2 = Mac::generate_u(&t);

        // U(t) should be deterministic
        assert_eq!(u1, u2);
    }

    #[test]
    fn test_generate_u_different_t() {
        let t1 = Scalar::one();
        let t2 = Scalar::one() + Scalar::one();

        let u1 = Mac::generate_u(&t1);
        let u2 = Mac::generate_u(&t2);

        // Different t values should produce different U values
        assert_ne!(u1, u2);
    }
}

