use crate::crypto::{GroupElement, Scalar};
use elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, ProjectivePoint};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

lazy_static! {
    /// Base point defined in the secp256k1 standard (ECDSA generator)
    pub static ref G: GroupElement = GroupElement::from_projective(ProjectivePoint::GENERATOR);

    /// Generator point for MAC and Show
    pub static ref GW: GroupElement = from_text("Gw");

    /// Generator point for MAC and Show
    pub static ref GWP: GroupElement = from_text("Gwp");

    /// Generator point for MAC and Show
    pub static ref GX0: GroupElement = from_text("Gx0");

    /// Generator point for MAC and Show
    pub static ref GX1: GroupElement = from_text("Gx1");

    /// Generator point for MAC and Show
    pub static ref GV: GroupElement = from_text("GV");

    /// Generator point for Pedersen commitments
    pub static ref GG: GroupElement = from_text("Gg");

    /// Generator point for Pedersen commitments
    pub static ref GH: GroupElement = from_text("Gh");

    /// Generator point for attributes M_{ai}
    pub static ref GA: GroupElement = from_text("Ga");

    /// Generator point for serial numbers
    pub static ref GS: GroupElement = from_text("Gs");

    /// Scalars corresponding to 2^i, used in range proofs (up to 255 bits)
    pub static ref SCALAR_POWERS_OF_TWO: Vec<Scalar> = {
        let mut powers = Vec::with_capacity(255);
        let mut current = Scalar::one();
        let two = Scalar::one() + Scalar::one();
        powers.push(current);
        for _ in 1..255 {
            current = current * two;
            powers.push(current);
        }
        powers
    };

    /// Generators corresponding to -(2^i) * Gh, used in range proofs
    pub static ref NEGATED_GH_POWERS_OF_TWO: Vec<GroupElement> = {
        SCALAR_POWERS_OF_TWO
            .iter()
            .map(|scalar| {
                let neg_scalar = scalar.negate();
                (&neg_scalar * &*GH).expect("scalar multiplication should succeed")
            })
            .collect()
    };
}

/// Collection of all generators for convenient access
pub struct Generators;

impl Generators {
    pub fn g() -> &'static GroupElement {
        &G
    }

    pub fn gw() -> &'static GroupElement {
        &GW
    }

    pub fn gwp() -> &'static GroupElement {
        &GWP
    }

    pub fn gx0() -> &'static GroupElement {
        &GX0
    }

    pub fn gx1() -> &'static GroupElement {
        &GX1
    }

    pub fn gv() -> &'static GroupElement {
        &GV
    }

    pub fn gg() -> &'static GroupElement {
        &GG
    }

    pub fn gh() -> &'static GroupElement {
        &GH
    }

    pub fn ga() -> &'static GroupElement {
        &GA
    }

    pub fn gs() -> &'static GroupElement {
        &GS
    }

    pub fn scalar_powers_of_two() -> &'static [Scalar] {
        &SCALAR_POWERS_OF_TWO
    }

    pub fn negated_gh_powers_of_two() -> &'static [GroupElement] {
        &NEGATED_GH_POWERS_OF_TWO
    }

    /// Deterministically derive a group element from arbitrary text.
    ///
    /// Mirrors WalletWasabi `Generators.FromText`. Used by tests and by any
    /// caller that needs a labelled NUMS-style point.
    pub fn from_text(text: &str) -> GroupElement {
        from_text(text)
    }
}

/// Deterministically creates a group element from the given text.
///
/// Matches the WalletWasabi C# `GroupElement.FromText` construction:
/// hash the input with SHA256, treat the digest as a candidate x coordinate,
/// compute `y = sqrt(x^3 + 7) mod p`, and re-hash on failure. We use the
/// natural parity returned by `sqrt` (NOT BIP340 even-y normalization).
pub fn from_text(text: &str) -> GroupElement {
    from_bytes(text.as_bytes())
}

/// Deterministically creates a group element from the given bytes by hashing
/// to a curve point. See [`from_text`] for the construction.
pub(crate) fn from_bytes(buffer: &[u8]) -> GroupElement {
    let mut hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(buffer);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    };

    loop {
        if let Some(point) = try_lift_x(&hash) {
            return point;
        }
        let mut h = Sha256::new();
        h.update(hash);
        let out = h.finalize();
        hash.copy_from_slice(&out);
    }
}

/// Attempt to interpret `bytes` as an x coordinate and lift to a curve point.
///
/// Returns `None` if `bytes` is >= field modulus or `x^3 + 7` is a
/// non-residue.
fn try_lift_x(bytes: &[u8; 32]) -> Option<GroupElement> {
    let fb = FieldBytes::clone_from_slice(bytes);
    // x must be a valid field element (< p). FieldElement::from_repr enforces this.
    let x_opt = k256::FieldElement::from_repr(fb);
    if !bool::from(x_opt.is_some()) {
        return None;
    }
    let x = x_opt.unwrap();
    // y^2 = x^3 + 7 (b = 7 for secp256k1)
    let b = k256::FieldElement::from(7u64);
    let rhs = x.square() * x + b;
    let y_opt = rhs.sqrt();
    if !bool::from(y_opt.is_some()) {
        return None;
    }
    let y = y_opt.unwrap().normalize();
    let x = x.normalize();
    // Encode as SEC1 compressed and parse via GroupElement::from_bytes to keep
    // representation invariants consistent with the rest of the crate.
    let mut compressed = [0u8; 33];
    compressed[0] = if bool::from(y.is_odd()) { 0x03 } else { 0x02 };
    compressed[1..].copy_from_slice(&x.to_bytes());
    GroupElement::from_bytes(&compressed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_g() {
        let g = Generators::g();
        assert!(!g.is_infinity());
    }

    #[test]
    fn test_generators_deterministic() {
        let gw1 = from_text("Gw");
        let gw2 = from_text("Gw");
        assert_eq!(gw1, gw2);
    }

    #[test]
    fn test_generators_unique() {
        let gw = Generators::gw();
        let gh = Generators::gh();
        assert_ne!(gw, gh);
    }

    #[test]
    fn test_scalar_powers_of_two() {
        let powers = Generators::scalar_powers_of_two();
        assert!(!powers.is_empty());
        assert_eq!(powers[0], Scalar::one());
    }
}
