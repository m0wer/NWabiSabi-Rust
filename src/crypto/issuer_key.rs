use crate::crypto::{GroupElement, Scalar};
use crate::crypto::randomness::WabiSabiRandom;
use crate::error::{Result, WabiSabiError};
use serde::{Deserialize, Serialize};

/// Credential issuer secret key (5 random scalars)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialIssuerSecretKey {
    pub w: Scalar,
    pub wp: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
}

impl CredentialIssuerSecretKey {
    /// Generate a new random secret key. Loops on the (cryptographically
    /// negligible) chance that the source ever yields zero, so the resulting
    /// key always satisfies `try_from_scalars`.
    pub fn new<R: WabiSabiRandom>(rng: &mut R) -> Self {
        loop {
            let w = rng.get_scalar();
            let wp = rng.get_scalar();
            let x0 = rng.get_scalar();
            let x1 = rng.get_scalar();
            let ya = rng.get_scalar();
            if let Ok(sk) = Self::try_from_scalars(w, wp, x0, x1, ya) {
                return sk;
            }
        }
    }

    /// Construct from explicit scalars; rejects any zero component (which
    /// would make the credential system trivially insecure). The error names
    /// the offending field, mirroring the C# `ArgumentException` parameter.
    pub fn try_from_scalars(
        w: Scalar,
        wp: Scalar,
        x0: Scalar,
        x1: Scalar,
        ya: Scalar,
    ) -> Result<Self> {
        if w.is_zero() {
            return Err(WabiSabiError::ZeroScalar { name: "w" });
        }
        if wp.is_zero() {
            return Err(WabiSabiError::ZeroScalar { name: "wp" });
        }
        if x0.is_zero() {
            return Err(WabiSabiError::ZeroScalar { name: "x0" });
        }
        if x1.is_zero() {
            return Err(WabiSabiError::ZeroScalar { name: "x1" });
        }
        if ya.is_zero() {
            return Err(WabiSabiError::ZeroScalar { name: "ya" });
        }
        Ok(Self { w, wp, x0, x1, ya })
    }

    /// Compute the public parameters from this secret key
    ///
    /// Cw = w*Gw + wp*Gwp
    /// I  = Gv - x0*Gx0 - x1*Gx1 - ya*Ga
    ///
    /// I is constructed so that the issuer-side check
    ///   Z = CV - (w*Gw + x0*Cx0 + x1*Cx1 + ya*Ca)
    /// reduces to z*I when the credential was honestly randomized with z.
    pub fn compute_parameters(&self) -> crate::error::Result<CredentialIssuerParameters> {
        use crate::crypto::Generators;

        // Cw = w*Gw + wp*Gwp
        let cw = ((&self.w * Generators::gw())? + (&self.wp * Generators::gwp())?)?;

        // I = Gv - x0*Gx0 - x1*Gx1 - ya*Ga
        let x0_gx0 = (&self.x0 * Generators::gx0())?;
        let x1_gx1 = (&self.x1 * Generators::gx1())?;
        let ya_ga = (&self.ya * Generators::ga())?;
        let neg_sum = ((x0_gx0 + x1_gx1)? + ya_ga)?.negate()?;
        let i = (Generators::gv().clone() + neg_sum)?;

        Ok(CredentialIssuerParameters { cw, i })
    }
}

/// Credential issuer public parameters
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerParameters {
    /// Cw = w*Gw + wp*Gwp
    pub cw: GroupElement,
    /// I = ya*Ga
    pub i: GroupElement,
}

impl CredentialIssuerParameters {
    /// Construct from group elements; rejects the point at infinity to match
    /// the C# constructor.
    pub fn try_new(cw: GroupElement, i: GroupElement) -> Result<Self> {
        if cw.is_infinity() {
            return Err(WabiSabiError::PointAtInfinity { name: "cw" });
        }
        if i.is_infinity() {
            return Err(WabiSabiError::PointAtInfinity { name: "i" });
        }
        Ok(Self { cw, i })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;

    #[test]
    fn test_key_generation() {
        let mut rng = SecureRandom::new();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let params = sk.compute_parameters().unwrap();
        assert!(!params.cw.is_infinity());
        assert!(!params.i.is_infinity());
    }
}
