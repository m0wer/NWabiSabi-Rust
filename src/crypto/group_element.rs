//! secp256k1 group elements (curve points), backed by `k256::ProjectivePoint`.
//!
//! The canonical representation on the wire is a 33-byte compressed encoding
//! (matching SEC1 / WalletWasabi). Internally we keep a projective point for
//! fast arithmetic and lazily produce the compressed form when serializing.

use crate::crypto::scalar::Scalar;
use crate::error::{Result, WabiSabiError};
use elliptic_curve::group::{Group, GroupEncoding};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};
use subtle::ConstantTimeEq;

/// secp256k1 curve point. Wraps `k256::ProjectivePoint`.
#[derive(Clone, Copy, Debug)]
pub struct GroupElement {
    point: ProjectivePoint,
}

impl GroupElement {
    /// Build from a `k256::ProjectivePoint`.
    pub(crate) fn from_projective(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Borrow the underlying `ProjectivePoint`.
    pub(crate) fn projective(&self) -> &ProjectivePoint {
        &self.point
    }

    /// The point at infinity (additive identity).
    pub fn infinity() -> Self {
        Self {
            point: ProjectivePoint::IDENTITY,
        }
    }

    /// True iff this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        bool::from(self.point.is_identity())
    }

    /// Parse a 33-byte SEC1-compressed point. Returns `Err` for invalid
    /// encodings. Accepts the all-zero buffer as the point at infinity to
    /// match the legacy serialization used by C# WalletWasabi.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(WabiSabiError::InvalidGroupElement);
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(Self::infinity());
        }
        let encoded =
            EncodedPoint::from_bytes(bytes).map_err(|_| WabiSabiError::InvalidGroupElement)?;
        let aff = AffinePoint::from_encoded_point(&encoded);
        if bool::from(aff.is_some()) {
            Ok(Self {
                point: ProjectivePoint::from(aff.unwrap()),
            })
        } else {
            Err(WabiSabiError::InvalidGroupElement)
        }
    }

    /// Serialize to 33-byte SEC1-compressed form. Infinity serializes as
    /// 33 zero bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        if self.is_infinity() {
            return [0u8; 33];
        }
        let aff = self.point.to_affine();
        let encoded = aff.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// Negate the point. Infinity negates to itself.
    pub fn negate(&self) -> Result<Self> {
        Ok(Self {
            point: -self.point,
        })
    }

    /// Multiply by a scalar. Multiplication by zero yields infinity.
    pub fn multiply(&self, scalar: &Scalar) -> Result<Self> {
        Ok(Self {
            point: self.point * scalar.inner(),
        })
    }
}

// -- Arithmetic operators --------------------------------------------------

impl Add for GroupElement {
    type Output = Result<Self>;
    fn add(self, other: Self) -> Self::Output {
        Ok(Self {
            point: self.point + other.point,
        })
    }
}

impl Add for &GroupElement {
    type Output = Result<GroupElement>;
    fn add(self, other: Self) -> Self::Output {
        Ok(GroupElement {
            point: self.point + other.point,
        })
    }
}

impl Sub for GroupElement {
    type Output = Result<Self>;
    fn sub(self, other: Self) -> Self::Output {
        Ok(Self {
            point: self.point - other.point,
        })
    }
}

impl Sub for &GroupElement {
    type Output = Result<GroupElement>;
    fn sub(self, other: Self) -> Self::Output {
        Ok(GroupElement {
            point: self.point - other.point,
        })
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

// -- Equality / hash / serde ----------------------------------------------

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.point.to_bytes().ct_eq(&other.point.to_bytes()))
    }
}

impl Eq for GroupElement {}

impl std::hash::Hash for GroupElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Serialize for GroupElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let bytes = self.to_bytes();
        let mut seq = serializer.serialize_tuple(33)?;
        for byte in &bytes {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn random_point() -> GroupElement {
        let mut rng = thread_rng();
        let s = Scalar::random(&mut rng);
        let g = GroupElement::from_projective(ProjectivePoint::GENERATOR);
        (g * s).unwrap()
    }

    #[test]
    fn infinity_is_identity() {
        let inf = GroupElement::infinity();
        assert!(inf.is_infinity());
        let p = random_point();
        assert_eq!((inf.clone() + p.clone()).unwrap(), p);
    }

    #[test]
    fn round_trip_compressed() {
        let p = random_point();
        let bytes = p.to_bytes();
        let q = GroupElement::from_bytes(&bytes).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn infinity_round_trip() {
        let inf = GroupElement::infinity();
        let bytes = inf.to_bytes();
        assert_eq!(bytes, [0u8; 33]);
        let parsed = GroupElement::from_bytes(&bytes).unwrap();
        assert!(parsed.is_infinity());
    }

    #[test]
    fn zero_scalar_yields_infinity() {
        let p = random_point();
        let zero = Scalar::zero();
        let r = (zero * p).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn negation() {
        let p = random_point();
        let neg = p.negate().unwrap();
        let zero = (p + neg).unwrap();
        assert!(zero.is_infinity());
    }
}
