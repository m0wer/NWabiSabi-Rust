use crate::crypto::scalar::Scalar;
use crate::error::{Result, WabiSabiError};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::ops::{Add, Mul, Sub};

/// Wrapper around secp256k1 group element (elliptic curve point) with lazy affine evaluation
#[derive(Clone, Debug)]
pub struct GroupElement {
    /// Compressed public key representation (33 bytes)
    /// This is eagerly computed and serves as the canonical representation
    compressed: [u8; 33],

    /// Lazily computed secp256k1 PublicKey for operations
    /// OnceLock provides thread-safe lazy initialization
    public_key: OnceLock<secp256k1::PublicKey>,
}

impl GroupElement {
    /// Create a group element from a secp256k1 public key
    pub fn from_public_key(pk: secp256k1::PublicKey) -> Self {
        let compressed = pk.serialize();
        let public_key = OnceLock::new();
        let _ = public_key.set(pk); // Eagerly set since we already have it
        Self {
            compressed,
            public_key,
        }
    }

    /// Create group element from compressed bytes (33 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(WabiSabiError::InvalidGroupElement);
        }

        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(bytes);

        // Validate by attempting to parse
        secp256k1::PublicKey::from_slice(&compressed)
            .map_err(|_| WabiSabiError::InvalidGroupElement)?;

        Ok(Self {
            compressed,
            public_key: OnceLock::new(),
        })
    }

    /// Serialize to compressed format (33 bytes)
    pub fn to_bytes(&self) -> [u8; 33] {
        self.compressed
    }

    /// Get the point at infinity
    pub fn infinity() -> Self {
        // Point at infinity is represented as all zeros
        Self {
            compressed: [0u8; 33],
            public_key: OnceLock::new(),
        }
    }

    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        self.compressed[0] == 0
    }

    /// Get the underlying public key, computing it if needed
    fn public_key(&self) -> Result<&secp256k1::PublicKey> {
        if self.is_infinity() {
            return Err(WabiSabiError::InvalidGroupElement);
        }

        self.public_key.get_or_init(|| {
            secp256k1::PublicKey::from_slice(&self.compressed)
                .expect("Invalid compressed public key")
        });
        Ok(self.public_key.get().expect("public_key was just initialized"))
    }

    /// Negate the group element
    pub fn negate(&self) -> Result<Self> {
        if self.is_infinity() {
            return Ok(Self::infinity());
        }

        let pk = self.public_key()?;
        let negated = pk.negate(&secp256k1::Secp256k1::new());
        Ok(Self::from_public_key(negated))
    }

    /// Multiply by scalar (scalar * point)
    pub fn multiply(&self, scalar: &Scalar) -> Result<Self> {
        if self.is_infinity() {
            return Ok(Self::infinity());
        }

        let pk = self.public_key()?;
        let result = pk.mul_tweak(&secp256k1::Secp256k1::new(), scalar.inner())
            .map_err(|_| WabiSabiError::InvalidGroupElement)?;
        Ok(Self::from_public_key(result))
    }
}

impl Add for GroupElement {
    type Output = Result<Self>;

    fn add(self, other: Self) -> Self::Output {
        if self.is_infinity() {
            return Ok(other);
        }
        if other.is_infinity() {
            return Ok(self);
        }

        let pk1 = self.public_key()?;
        let pk2 = other.public_key()?;

        let result = pk1.combine(pk2)
            .map_err(|_| WabiSabiError::InvalidGroupElement)?;
        Ok(Self::from_public_key(result))
    }
}

impl Add for &GroupElement {
    type Output = Result<GroupElement>;

    fn add(self, other: Self) -> Self::Output {
        self.clone() + other.clone()
    }
}

impl Sub for GroupElement {
    type Output = Result<Self>;

    fn sub(self, other: Self) -> Self::Output {
        self + other.negate()?
    }
}

impl Sub for &GroupElement {
    type Output = Result<GroupElement>;

    fn sub(self, other: Self) -> Self::Output {
        self.clone() - other.clone()
    }
}

impl Mul<&GroupElement> for &Scalar {
    type Output = Result<GroupElement>;

    fn mul(self, ge: &GroupElement) -> Self::Output {
        ge.multiply(self)
    }
}

impl Mul<&Scalar> for &GroupElement {
    type Output = Result<GroupElement>;

    fn mul(self, scalar: &Scalar) -> Self::Output {
        self.multiply(scalar)
    }
}

impl Mul<&GroupElement> for Scalar {
    type Output = Result<GroupElement>;

    fn mul(self, ge: &GroupElement) -> Self::Output {
        ge.multiply(&self)
    }
}

impl Mul<GroupElement> for Scalar {
    type Output = Result<GroupElement>;

    fn mul(self, ge: GroupElement) -> Self::Output {
        ge.multiply(&self)
    }
}

impl Mul<GroupElement> for &Scalar {
    type Output = Result<GroupElement>;

    fn mul(self, ge: GroupElement) -> Self::Output {
        ge.multiply(self)
    }
}

impl Mul<Scalar> for &GroupElement {
    type Output = Result<GroupElement>;

    fn mul(self, scalar: Scalar) -> Self::Output {
        self.multiply(&scalar)
    }
}

impl Mul<Scalar> for GroupElement {
    type Output = Result<GroupElement>;

    fn mul(self, scalar: Scalar) -> Self::Output {
        self.multiply(&scalar)
    }
}

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        // Fast path: compare compressed representations
        self.compressed == other.compressed
    }
}

impl Eq for GroupElement {}

impl std::hash::Hash for GroupElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.compressed.hash(state);
    }
}

impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(33)?;
        for byte in &self.compressed {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_infinity() {
        let inf = GroupElement::infinity();
        assert!(inf.is_infinity());
    }

    #[test]
    fn test_serialization() {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let secp = secp256k1::Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut rng);
        let ge = GroupElement::from_public_key(pk);

        let bytes = ge.to_bytes();
        let deserialized = GroupElement::from_bytes(&bytes).unwrap();
        assert_eq!(ge, deserialized);
    }

    #[test]
    fn test_addition_identity() {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = thread_rng();
        let (_, pk) = secp.generate_keypair(&mut rng);
        let ge = GroupElement::from_public_key(pk);
        let inf = GroupElement::infinity();

        let result = (ge.clone() + inf).unwrap();
        assert_eq!(result, ge);
    }

    #[test]
    fn test_scalar_multiplication() {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = thread_rng();
        let (_, pk) = secp.generate_keypair(&mut rng);
        let ge = GroupElement::from_public_key(pk);
        let scalar = Scalar::one();

        let result = (&scalar * &ge).unwrap();
        assert_eq!(result, ge);
    }
}
