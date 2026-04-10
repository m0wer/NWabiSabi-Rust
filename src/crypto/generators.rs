use crate::crypto::{GroupElement, Scalar};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

lazy_static! {
    /// Base point defined in the secp256k1 standard (ECDSA generator)
    pub static ref G: GroupElement = {
        let secp = secp256k1::Secp256k1::new();
        let generator = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
                .expect("valid secret key")
        );
        GroupElement::from_public_key(generator)
    };

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
}

/// Deterministically creates a group element from the given text
/// Uses SHA256 hash-to-curve construction
pub fn from_text(text: &str) -> GroupElement {
    from_bytes(text.as_bytes())
}

/// Deterministically creates a group element from the given bytes
/// Uses SHA256 hash-to-curve construction with rejection sampling
pub(crate) fn from_bytes(buffer: &[u8]) -> GroupElement {
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let mut hash = hasher.finalize();

    loop {
        // Try to create a valid public key from the hash
        // Use the hash as an x-coordinate and try both y parities
        if let Ok(ge) = try_create_point_from_hash(&hash) {
            return ge;
        }

        // If failed, re-hash
        hasher = Sha256::new();
        hasher.update(&hash);
        hash = hasher.finalize();
    }
}

fn try_create_point_from_hash(hash: &[u8]) -> Result<GroupElement, ()> {
    // Try to create compressed public key with even parity
    let mut compressed_even = [0u8; 33];
    compressed_even[0] = 0x02; // Even parity
    compressed_even[1..].copy_from_slice(&hash[..32]);

    if let Ok(ge) = GroupElement::from_bytes(&compressed_even) {
        return Ok(ge);
    }

    // Try odd parity
    let mut compressed_odd = [0u8; 33];
    compressed_odd[0] = 0x03; // Odd parity
    compressed_odd[1..].copy_from_slice(&hash[..32]);

    if let Ok(ge) = GroupElement::from_bytes(&compressed_odd) {
        return Ok(ge);
    }

    Err(())
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
