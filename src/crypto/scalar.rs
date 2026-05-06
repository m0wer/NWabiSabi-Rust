//! Scalars over the secp256k1 group order, backed by `k256::Scalar`.
//!
//! This module exposes a thin newtype around `k256::Scalar` that provides the
//! arithmetic the rest of the WabiSabi crate needs: add / sub / mul / neg /
//! inverse / equality, plus serialization as 32 big-endian bytes (matching the
//! reference C# WalletWasabi serialization).

use crate::error::{Result, WabiSabiError};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::ops::Reduce;
use k256::Scalar as KScalar;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg, Sub};
use subtle::ConstantTimeEq;

/// Wrapper around `k256::Scalar` for field operations on the secp256k1 scalar group.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scalar(KScalar);

impl Scalar {
    /// Zero scalar.
    pub fn zero() -> Self {
        Self(KScalar::ZERO)
    }

    /// One scalar.
    pub fn one() -> Self {
        Self(KScalar::ONE)
    }

    /// Generate a uniformly random scalar.
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        // k256::Scalar::random uses a CryptoRng; we wrap any Rng by sampling
        // 32 bytes and reducing.
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(<KScalar as Reduce<k256::U256>>::reduce_bytes(&bytes.into()))
    }

    /// Construct from 32 big-endian bytes. Returns `Err` if the value is >= n.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let opt = KScalar::from_repr((*bytes).into());
        if bool::from(opt.is_some()) {
            Ok(Self(opt.unwrap()))
        } else {
            Err(WabiSabiError::InvalidScalar)
        }
    }

    /// Construct from 32 big-endian bytes, reducing modulo n.
    pub fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
        Self(<KScalar as Reduce<k256::U256>>::reduce_bytes(bytes.into()))
    }

    /// Construct from a `u64` (always succeeds; value < n).
    pub fn from_u64(value: u64) -> Self {
        // k256::Scalar implements From<u64>.
        Self(KScalar::from(value))
    }

    /// Construct from an `i64`. Negative values are mapped to their additive
    /// inverse modulo n. Always succeeds.
    pub fn from_i64(value: i64) -> Self {
        if value >= 0 {
            Self::from_u64(value as u64)
        } else {
            // -|value| mod n
            let abs = (value as i128).unsigned_abs() as u64;
            Self::from_u64(abs).negate()
        }
    }

    /// Convenience: build directly from a `k256::Scalar`.
    pub(crate) fn from_inner(s: KScalar) -> Self {
        Self(s)
    }

    /// Borrow the underlying `k256::Scalar`.
    pub(crate) fn inner(&self) -> &KScalar {
        &self.0
    }

    /// Serialize as 32 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// Negate (`n - self mod n`). `0` negates to `0`.
    pub fn negate(&self) -> Self {
        Self(self.0.negate())
    }

    /// Multiplicative inverse. Returns `Err` for the zero scalar.
    pub fn invert(&self) -> Result<Self> {
        let inv = self.0.invert();
        if bool::from(inv.is_some()) {
            Ok(Self(inv.unwrap()))
        } else {
            Err(WabiSabiError::InvalidScalar)
        }
    }

    /// Constant-time check for zero.
    pub fn is_zero(&self) -> bool {
        bool::from(self.0.is_zero())
    }
}

// -- Operator impls ---------------------------------------------------------

impl Add for Scalar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for Scalar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Mul for Scalar {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self {
        self.negate()
    }
}

impl Add for &Scalar {
    type Output = Scalar;
    fn add(self, other: Self) -> Scalar {
        Scalar(self.0 + other.0)
    }
}

impl Sub for &Scalar {
    type Output = Scalar;
    fn sub(self, other: Self) -> Scalar {
        Scalar(self.0 - other.0)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;
    fn mul(self, other: Self) -> Scalar {
        Scalar(self.0 * other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Scalar {}

impl std::hash::Hash for Scalar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

// -- Serde -----------------------------------------------------------------

impl Serialize for Scalar {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        serde_bytes::serialize(&bytes[..], serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes for Scalar, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr).map_err(|_| serde::de::Error::custom("scalar >= group order"))
    }
}

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn zero_one() {
        assert!(Scalar::zero().is_zero());
        assert!(!Scalar::one().is_zero());
        assert_eq!(Scalar::zero() + Scalar::one(), Scalar::one());
    }

    #[test]
    fn addition_commutes() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        assert_eq!(a + b, b + a);
    }

    #[test]
    fn negation_round_trip() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        assert_eq!(a + a.negate(), Scalar::zero());
        assert_eq!(-a, a.negate());
    }

    #[test]
    fn invert_round_trip() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let inv = a.invert().unwrap();
        assert_eq!(a * inv, Scalar::one());
        assert!(Scalar::zero().invert().is_err());
    }

    #[test]
    fn from_u64_matches_repeated_addition() {
        let s = Scalar::from_u64(5);
        let mut acc = Scalar::zero();
        for _ in 0..5 {
            acc = acc + Scalar::one();
        }
        assert_eq!(s, acc);
    }

    #[test]
    fn from_i64_negative() {
        let pos = Scalar::from_u64(7);
        let neg = Scalar::from_i64(-7);
        assert_eq!(pos + neg, Scalar::zero());
    }

    #[test]
    fn serde_round_trip() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let bytes = a.to_bytes();
        let b = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }
}
