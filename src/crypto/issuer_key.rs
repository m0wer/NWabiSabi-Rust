use crate::crypto::{GroupElement, Scalar};
use crate::crypto::randomness::WabiSabiRandom;
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
    /// Generate a new random secret key
    pub fn new<R: WabiSabiRandom>(rng: &mut R) -> Self {
        Self {
            w: rng.get_scalar(),
            wp: rng.get_scalar(),
            x0: rng.get_scalar(),
            x1: rng.get_scalar(),
            ya: rng.get_scalar(),
        }
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
