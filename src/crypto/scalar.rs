use crate::error::{Result, WabiSabiError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg, Sub};

/// secp256k1 curve order (n) in big-endian
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Wrapper around secp256k1 scalar for field operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scalar(#[serde(with = "scalar_serde")] secp256k1::Scalar);

mod scalar_serde {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &secp256k1::Scalar, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = scalar.to_be_bytes();
        serde_bytes::serialize(&bytes[..], serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<secp256k1::Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes for Scalar, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        secp256k1::Scalar::from_be_bytes(array)
            .map_err(|_| serde::de::Error::custom("Invalid scalar bytes"))
    }
}

impl Scalar {
    /// Zero scalar
    pub fn zero() -> Self {
        Self(secp256k1::Scalar::ZERO)
    }

    /// One scalar
    pub fn one() -> Self {
        Self(secp256k1::Scalar::ONE)
    }

    /// Generate a random scalar
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill(&mut bytes);
            if let Ok(scalar) = secp256k1::Scalar::from_be_bytes(bytes) {
                return Self(scalar);
            }
        }
    }

    /// Create scalar from big-endian bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        secp256k1::Scalar::from_be_bytes(*bytes)
            .map(Self)
            .map_err(|_| WabiSabiError::InvalidScalar)
    }

    /// Create scalar from an i64 value
    pub fn from_i64(value: i64) -> Result<Self> {
        // Convert i64 to little-endian bytes, then to scalar
        let mut bytes = [0u8; 32];
        let value_bytes = value.to_le_bytes();
        bytes[..8].copy_from_slice(&value_bytes);

        // For negative values, we need proper two's complement representation
        if value < 0 {
            // Fill the upper bytes with 0xFF for sign extension
            bytes[8..].fill(0xFF);
        }

        // Convert from little-endian to big-endian for secp256k1
        bytes.reverse();

        Self::from_bytes(&bytes)
    }

    /// Convert scalar to big-endian bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Negate the scalar (n - self mod n)
    pub fn negate(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        // Compute n - self
        let self_bytes = self.0.to_be_bytes();
        let result = scalar_sub_mod_n(&SECP256K1_ORDER, &self_bytes);
        Self(secp256k1::Scalar::from_be_bytes(result).expect("negation should produce valid scalar"))
    }

    /// Get the underlying secp256k1 scalar
    pub(crate) fn inner(&self) -> &secp256k1::Scalar {
        &self.0
    }

    /// Create from inner secp256k1 scalar
    pub(crate) fn from_inner(inner: secp256k1::Scalar) -> Self {
        Self(inner)
    }

    /// Check if scalar is zero
    pub fn is_zero(&self) -> bool {
        self.0 == secp256k1::Scalar::ZERO
    }

    /// Create scalar from u64
    pub fn from_u64(value: u64) -> Result<Self> {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self::from_bytes(&bytes)
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let a = self.0.to_be_bytes();
        let b = other.0.to_be_bytes();
        let result = scalar_add_mod_n(&a, &b);
        Self(secp256k1::Scalar::from_be_bytes(result).expect("addition should produce valid scalar"))
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + other.negate()
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let a = self.0.to_be_bytes();
        let b = other.0.to_be_bytes();
        let result = scalar_mul_mod_n(&a, &b);
        Self(secp256k1::Scalar::from_be_bytes(result).expect("multiplication should produce valid scalar"))
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        self.negate()
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self::from_u64(value).expect("u64 should always fit in a scalar")
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    fn mul(self, other: Self) -> Scalar {
        *self * *other
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    fn add(self, other: Self) -> Scalar {
        *self + *other
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    fn sub(self, other: Self) -> Scalar {
        *self - *other
    }
}

// Helper functions for scalar arithmetic modulo n

/// Add two 256-bit big-endian integers (no reduction)
fn add_256(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;

    for i in (0..32).rev() {
        let sum = (a[i] as u16) + (b[i] as u16) + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }

    (result, carry > 0)
}

/// Subtract two 256-bit big-endian integers (a - b), returns (result, borrowed)
fn sub_256(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;

    for i in (0..32).rev() {
        let diff = (a[i] as i16) - (b[i] as i16) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    (result, borrow > 0)
}

/// Add two 256-bit big-endian integers modulo n
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (result, carry) = add_256(a, b);

    // Reduce modulo n if result >= n
    if carry || compare_be(&result, &SECP256K1_ORDER) >= 0 {
        let (reduced, _) = sub_256(&result, &SECP256K1_ORDER);
        return reduced;
    }

    result
}

/// Subtract two 256-bit big-endian integers modulo n
fn scalar_sub_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (result, borrowed) = sub_256(a, b);

    // If there's a borrow, we need to add n back
    if borrowed {
        let (added, _) = add_256(&result, &SECP256K1_ORDER);
        return added;
    }

    result
}

/// Multiply two 256-bit big-endian integers modulo n
fn scalar_mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Use 512-bit intermediate result
    let mut product = [0u64; 8]; // 8 x 64-bit = 512 bits

    // Convert to 32-bit limbs for easier multiplication (big-endian)
    let a_limbs: [u64; 4] = [
        u64::from_be_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]),
        u64::from_be_bytes([a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]]),
        u64::from_be_bytes([a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23]]),
        u64::from_be_bytes([a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31]]),
    ];
    let b_limbs: [u64; 4] = [
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
    ];

    // Schoolbook multiplication with 32-bit limbs to avoid overflow
    for i in 0..4 {
        for j in 0..4 {
            let a_lo = a_limbs[3 - i] & 0xFFFF_FFFF;
            let a_hi = a_limbs[3 - i] >> 32;
            let b_lo = b_limbs[3 - j] & 0xFFFF_FFFF;
            let b_hi = b_limbs[3 - j] >> 32;

            // Karatsuba-style splitting to avoid overflow
            let lo_lo = a_lo * b_lo;
            let hi_hi = a_hi * b_hi;
            let mid1 = a_lo * b_hi;
            let mid2 = a_hi * b_lo;

            // Add to product array
            let idx = 7 - (i + j) / 2;
            let idx2 = 7 - ((i + j) / 2 + 1);
            let shift = ((i + j) % 2) * 32;

            if shift == 0 {
                let (sum, overflow1) = product[idx].overflowing_add(lo_lo);
                product[idx] = sum;
                if overflow1 && idx > 0 {
                    product[idx - 1] = product[idx - 1].wrapping_add(1);
                }

                let (sum, _) = product[idx].overflowing_add((mid1 & 0xFFFF_FFFF) << 32);
                product[idx] = sum;
                let (sum, _) = product[idx].overflowing_add((mid2 & 0xFFFF_FFFF) << 32);
                product[idx] = sum;

                if idx > 0 {
                    product[idx - 1] = product[idx - 1].wrapping_add(mid1 >> 32);
                    product[idx - 1] = product[idx - 1].wrapping_add(mid2 >> 32);
                    product[idx - 1] = product[idx - 1].wrapping_add(hi_hi);
                }
            } else {
                // Cross-limb case
                let (sum, _) = product[idx].overflowing_add(lo_lo << 32);
                product[idx] = sum;
                if idx > 0 {
                    product[idx - 1] = product[idx - 1].wrapping_add(lo_lo >> 32);
                    product[idx - 1] = product[idx - 1].wrapping_add(mid1);
                    product[idx - 1] = product[idx - 1].wrapping_add(mid2);
                }
                if idx > 1 {
                    product[idx - 2] = product[idx - 2].wrapping_add(hi_hi);
                }
            }
        }
    }

    // Reduce modulo n using simple division
    reduce_mod_n(&product)
}

/// Compare two 32-byte big-endian numbers
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
fn compare_be(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

/// Reduce a 512-bit number modulo n
fn reduce_mod_n(product: &[u64; 8]) -> [u8; 32] {
    // Convert product to bytes
    let mut bytes = [0u8; 64];
    for (i, &limb) in product.iter().enumerate() {
        let limb_bytes = limb.to_be_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }

    // Simple reduction: repeatedly subtract n while >= n
    // Start from high bytes
    let n_extended = {
        let mut n = [0u8; 64];
        n[32..64].copy_from_slice(&SECP256K1_ORDER);
        n
    };

    let mut result = bytes;

    // Reduce by subtracting 2^256 * n, 2^224 * n, etc.
    // For simplicity, we do a series of conditional subtractions
    for shift in (0..=32).rev() {
        let mut shifted_n = [0u8; 64];
        let start = 32 - shift;
        if start + 32 <= 64 {
            shifted_n[start..start + 32].copy_from_slice(&SECP256K1_ORDER);

            while compare_64(&result, &shifted_n) >= 0 {
                result = sub_64(&result, &shifted_n);
            }
        }
    }

    // Extract lower 32 bytes
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[32..64]);

    // Final reduction
    while compare_be(&output, &SECP256K1_ORDER) >= 0 {
        output = scalar_sub_mod_n(&output, &SECP256K1_ORDER);
    }

    output
}

fn compare_64(a: &[u8; 64], b: &[u8; 64]) -> i32 {
    for i in 0..64 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

fn sub_64(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let mut borrow: i16 = 0;

    for i in (0..64).rev() {
        let diff = (a[i] as i16) - (b[i] as i16) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_scalar_zero_one() {
        assert!(Scalar::zero().is_zero());
        assert!(!Scalar::one().is_zero());
    }

    #[test]
    fn test_scalar_addition() {
        let a = Scalar::one();
        let b = Scalar::one();
        let c = a + b;
        assert_ne!(c, Scalar::zero());
    }

    #[test]
    fn test_scalar_negation() {
        let a = Scalar::one();
        let neg_a = a.negate();
        assert_eq!(a + neg_a, Scalar::zero());
    }

    #[test]
    fn test_scalar_serialization() {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let bytes = scalar.to_bytes();
        let deserialized = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }
}
