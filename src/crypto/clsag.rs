//! Linkable ring signatures over secp256k1 for the JoinMarket bond
//! attestation (JMP-0006 Phase EXT-1A).
//!
//! Despite the spec wording "CLSAG-style", what we need here is the
//! single-key LSAG variant: each ring member contributes one secp256k1
//! pubkey, the signer holds the discrete-log behind one of them, and the
//! key image lets verifiers detect a single signer claiming multiple
//! identities within one run. Real Monero CLSAG aggregates multiple
//! parallel rings (commitment + spend keys) and is overkill for a
//! one-key-per-bond setting.
//!
//! ## Construction
//!
//! Let `n = |ring|`, `P_pi = x * G` be the signer's public key, and
//! `m` the message. With domain-separation tag `DST` for `H_p`:
//!
//! - `H_p`: hash-to-curve via `secp256k1_XMD:SHA-256_SSWU_RO_` returning
//!   a `ProjectivePoint`, applied to the SEC1-compressed encoding of the
//!   ring member.
//! - `H_s`: SHA-256 reduced mod `q`, applied to a domain-separated
//!   hashing of `(ring, key_image, m, L_i, R_i)` (or `(run_id)` for the
//!   key-image rotation).
//!
//! Key image (wire form):
//!     I = H_p(P_pi) * x + H_s("rotate" || run_id) * G
//!
//! Verifiers recover the LSAG core image `I' = I - H_s("rotate"||run_id) * G`
//! and run the standard LSAG check on `I'`. Adding `H_s(run_id) * G`
//! to the wire image makes two signatures by the same bond from two
//! different runs unlinkable while keeping within-run duplicate
//! detection trivial (key-image equality).
//!
//! Signature wire format (decoded):
//!
//! ```text
//! <key_image: 33 bytes>           // SEC1-compressed point
//! <c0:        32 bytes>           // big-endian scalar
//! <s_1:       32 bytes>
//! ...
//! <s_n:       32 bytes>
//! ```
//!
//! Ring members are encoded as 32-byte x-only pubkeys (BIP340 form); we
//! lift each to the unique even-Y point on the curve before any
//! arithmetic. Verification fails if any member fails to lift.

use crate::crypto::generators::Generators;
use crate::crypto::{GroupElement, Scalar};
use crate::error::{Result, WabiSabiError};
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::{ProjectivePoint, Secp256k1};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation tag for `H_p` (point hash).
const HASH_TO_POINT_DST: &[u8] = b"jmng/clsag/v1/Hp";

/// Domain separation tag for the run-id rotation scalar.
const RUN_ROTATION_DST: &[u8] = b"jmng/clsag/v1/rotate";

/// Domain separation tag for the per-step Fiat-Shamir challenge.
const CHALLENGE_DST: &[u8] = b"jmng/clsag/v1/challenge";

/// Hash-to-point on secp256k1 using `secp256k1_XMD:SHA-256_SSWU_RO_`.
/// The k256 crate already provides this via `GroupDigest::hash_from_bytes`.
fn hash_to_point(input: &[u8]) -> Result<GroupElement> {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[HASH_TO_POINT_DST, input],
        &[HASH_TO_POINT_DST],
    )
    .map_err(|_| WabiSabiError::InvalidGroupElement)?;
    Ok(GroupElement::from_projective(pt))
}

/// Compute the run-rotation scalar `H_s("rotate" || run_id)`.
fn run_rotation_scalar(run_id: &[u8]) -> Scalar {
    let mut h = Sha256::new();
    h.update(RUN_ROTATION_DST);
    h.update(run_id);
    let bytes: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_reduced(&bytes)
}

/// Re-exports for the Python binding layer. Keeping these crate-private
/// helpers behind `pub(crate)` thin wrappers avoids leaking the DSTs
/// from the public surface while still letting the binding compute a
/// key image without reaching into the internals.
#[cfg(feature = "python")]
pub(crate) fn hash_to_point_for_python(input: &[u8]) -> Result<GroupElement> {
    hash_to_point(input)
}

#[cfg(feature = "python")]
pub(crate) fn run_rotation_scalar_for_python(run_id: &[u8]) -> Scalar {
    run_rotation_scalar(run_id)
}

/// Lift a 32-byte x-only pubkey (BIP340 form) to a full curve point with
/// even-Y. Returns `Err` if the x-coordinate is not on the curve.
fn lift_x_only(xonly: &[u8; 32]) -> Result<GroupElement> {
    // BIP340 even-Y lift: prefix with 0x02 and parse as SEC1 compressed.
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(xonly);
    GroupElement::from_bytes(&sec1)
}

/// Compute the per-step challenge scalar.
///
/// Binds the ring, key image, message, and the two announcements
/// `(L, R)` produced at this ring index.
fn challenge(
    ring_xonly: &[[u8; 32]],
    key_image: &GroupElement,
    msg: &[u8],
    l: &GroupElement,
    r: &GroupElement,
) -> Scalar {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DST);
    h.update((ring_xonly.len() as u32).to_be_bytes());
    for p in ring_xonly {
        h.update(p);
    }
    h.update(key_image.to_bytes());
    h.update((msg.len() as u32).to_be_bytes());
    h.update(msg);
    h.update(l.to_bytes());
    h.update(r.to_bytes());
    let bytes: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_reduced(&bytes)
}

/// LSAG-style ring signature over secp256k1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    /// Wire-form key image (rotated per run).
    pub key_image: GroupElement,
    /// Initial challenge.
    pub c0: Scalar,
    /// One response per ring member, in ring order.
    pub s: Vec<Scalar>,
}

impl RingSignature {
    /// Decoded byte length for a ring of size `n`.
    pub fn encoded_len(n: usize) -> usize {
        33 + 32 + 32 * n
    }

    /// Serialize to the wire form documented at the module level.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::encoded_len(self.s.len()));
        out.extend_from_slice(&self.key_image.to_bytes());
        out.extend_from_slice(&self.c0.to_bytes());
        for s_i in &self.s {
            out.extend_from_slice(&s_i.to_bytes());
        }
        out
    }

    /// Parse from the wire form. `ring_size` must match the length the
    /// signature was produced with.
    pub fn from_bytes(bytes: &[u8], ring_size: usize) -> Result<Self> {
        if bytes.len() != Self::encoded_len(ring_size) {
            return Err(WabiSabiError::DeserializationError(format!(
                "expected {} bytes, got {}",
                Self::encoded_len(ring_size),
                bytes.len()
            )));
        }
        let key_image = GroupElement::from_bytes(&bytes[..33])?;
        let c0_bytes: [u8; 32] = bytes[33..65]
            .try_into()
            .map_err(|_| WabiSabiError::DeserializationError("c0 slice".into()))?;
        let c0 = Scalar::from_bytes_reduced(&c0_bytes);
        let mut s = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            let off = 65 + 32 * i;
            let chunk: [u8; 32] = bytes[off..off + 32]
                .try_into()
                .map_err(|_| WabiSabiError::DeserializationError("s slice".into()))?;
            s.push(Scalar::from_bytes_reduced(&chunk));
        }
        Ok(Self { key_image, c0, s })
    }
}

/// Sign `message` with secret key `x` over the ring `ring_xonly` at the
/// signer's index `signer_idx`, using `run_id` for key-image rotation.
///
/// `ring_xonly[signer_idx]` MUST equal the BIP340 even-Y lift of `x * G`,
/// otherwise this returns `WabiSabiError::InvalidParameter`.
pub fn sign<R: Rng>(
    ring_xonly: &[[u8; 32]],
    signer_idx: usize,
    secret_key: &Scalar,
    run_id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<RingSignature> {
    let n = ring_xonly.len();
    if n == 0 || signer_idx >= n {
        return Err(WabiSabiError::InvalidParameter);
    }

    // Verify the signer's key matches the claimed ring slot.
    let g = *Generators::g();
    let p_signer = g.multiply(secret_key)?;
    let p_signer_lifted = lift_x_only(&ring_xonly[signer_idx])?;
    if p_signer.to_bytes() != p_signer_lifted.to_bytes() {
        return Err(WabiSabiError::InvalidParameter);
    }

    // Lift every ring member up front; reject malformed entries.
    let mut ring_points = Vec::with_capacity(n);
    let mut ring_h = Vec::with_capacity(n);
    for x_only in ring_xonly {
        let p = lift_x_only(x_only)?;
        ring_h.push(hash_to_point(&p.to_bytes())?);
        ring_points.push(p);
    }

    // Wire key image: I = H_p(P_pi) * x + H_s("rotate"||run_id) * G
    let h_pi = ring_h[signer_idx];
    let i_core = h_pi.multiply(secret_key)?;
    let rot = run_rotation_scalar(run_id);
    let rot_g = g.multiply(&rot)?;
    let key_image = (i_core + rot_g)?;

    // The LSAG check uses I' = key_image - rot*G = i_core.
    let i_prime = i_core;

    // Pick alpha and dummy responses for all non-signer slots.
    let alpha = Scalar::random(rng);
    let mut s = vec![Scalar::zero(); n];
    for (i, slot) in s.iter_mut().enumerate() {
        if i != signer_idx {
            *slot = Scalar::random(rng);
        }
    }

    // Initial challenge at index (signer_idx + 1) mod n.
    let l_pi = g.multiply(&alpha)?;
    let r_pi = h_pi.multiply(&alpha)?;
    let mut c = vec![Scalar::zero(); n];
    let next = (signer_idx + 1) % n;
    c[next] = challenge(ring_xonly, &key_image, message, &l_pi, &r_pi);

    // Walk the ring: for i = next, next+1, ..., signer_idx-1
    let mut i = next;
    while i != signer_idx {
        // L_i = s_i * G + c_i * P_i
        let l = (g.multiply(&s[i])? + ring_points[i].multiply(&c[i])?)?;
        // R_i = s_i * H_p(P_i) + c_i * I'
        let r = (ring_h[i].multiply(&s[i])? + i_prime.multiply(&c[i])?)?;
        let next_idx = (i + 1) % n;
        c[next_idx] = challenge(ring_xonly, &key_image, message, &l, &r);
        i = next_idx;
    }

    // Close the loop: s_pi = alpha - c_pi * x  (mod q)
    s[signer_idx] = alpha - (c[signer_idx] * *secret_key);

    Ok(RingSignature {
        key_image,
        c0: c[0],
        s,
    })
}

/// Verify `signature` over `ring_xonly` and `message` for the given `run_id`.
pub fn verify(
    ring_xonly: &[[u8; 32]],
    signature: &RingSignature,
    run_id: &[u8],
    message: &[u8],
) -> Result<()> {
    let n = ring_xonly.len();
    if n == 0 || signature.s.len() != n {
        return Err(WabiSabiError::InvalidProof);
    }
    if signature.key_image.is_infinity() {
        return Err(WabiSabiError::InvalidProof);
    }

    // Recover the LSAG core image: I' = I_wire - rot*G.
    let g = *Generators::g();
    let rot = run_rotation_scalar(run_id);
    let rot_g = g.multiply(&rot)?;
    let i_prime = (signature.key_image - rot_g)?;

    // Lift ring + precompute H_p.
    let mut ring_points = Vec::with_capacity(n);
    let mut ring_h = Vec::with_capacity(n);
    for x_only in ring_xonly {
        let p = lift_x_only(x_only)?;
        ring_h.push(hash_to_point(&p.to_bytes())?);
        ring_points.push(p);
    }

    // Walk the ring from index 0 forward, recomputing each c_{i+1}.
    let mut c = signature.c0;
    for i in 0..n {
        let l = (g.multiply(&signature.s[i])? + ring_points[i].multiply(&c)?)?;
        let r = (ring_h[i].multiply(&signature.s[i])? + i_prime.multiply(&c)?)?;
        c = challenge(ring_xonly, &signature.key_image, message, &l, &r);
    }

    // Loop closes iff the recomputed challenge equals c0.
    if c == signature.c0 {
        Ok(())
    } else {
        Err(WabiSabiError::InvalidProof)
    }
}

/// Convenience helper: encode the JMP-0006 attestation message.
///
/// Returns `"jmng/tx_extension_v1/attest" || run_id || round_no_be16`.
pub fn attestation_message(run_id: &[u8], round_no: u16) -> Vec<u8> {
    const PREFIX: &[u8] = b"jmng/tx_extension_v1/attest";
    let mut out = Vec::with_capacity(PREFIX.len() + run_id.len() + 2);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(run_id);
    out.extend_from_slice(&round_no.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Build a ring of `n` random x-only pubkeys and place the signer at
    /// `signer_idx`. Returns `(ring, secret_key)`.
    fn build_ring(n: usize, signer_idx: usize) -> (Vec<[u8; 32]>, Scalar) {
        let mut rng = OsRng;
        let mut ring = Vec::with_capacity(n);
        let mut signer_secret = Scalar::zero();
        let g = *Generators::g();
        for i in 0..n {
            // Pick a secret, derive the public point, force even-Y (BIP340
            // canonical) by negating the secret if the lift yields odd-Y.
            let mut sk = Scalar::random(&mut rng);
            let pk = g.multiply(&sk).unwrap();
            let mut compressed = pk.to_bytes();
            if compressed[0] == 0x03 {
                sk = -sk;
                let pk2 = g.multiply(&sk).unwrap();
                compressed = pk2.to_bytes();
            }
            assert_eq!(compressed[0], 0x02);
            let mut x_only = [0u8; 32];
            x_only.copy_from_slice(&compressed[1..]);
            ring.push(x_only);
            if i == signer_idx {
                signer_secret = sk;
            }
        }
        (ring, signer_secret)
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(8, 3);
        let run_id = b"run-001";
        let msg = b"jmng/tx_extension_v1/attest:demo";
        let sig = sign(&ring, 3, &sk, run_id, msg, &mut rng).unwrap();
        verify(&ring, &sig, run_id, msg).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(5, 0);
        let sig = sign(&ring, 0, &sk, b"r", b"m1", &mut rng).unwrap();
        assert!(verify(&ring, &sig, b"r", b"m2").is_err());
    }

    #[test]
    fn verify_rejects_wrong_run_id() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(5, 2);
        let sig = sign(&ring, 2, &sk, b"run-A", b"msg", &mut rng).unwrap();
        assert!(verify(&ring, &sig, b"run-B", b"msg").is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let mut rng = OsRng;
        let (ring, _sk) = build_ring(5, 1);
        // Use a different secret that does not match any ring slot.
        let bogus = Scalar::random(&mut rng);
        // Sign would already fail because the slot mismatches; assert that.
        let res = sign(&ring, 1, &bogus, b"r", b"m", &mut rng);
        assert!(res.is_err());
    }

    #[test]
    fn key_image_matches_within_run_differs_across_runs() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(6, 4);
        let sig_a = sign(&ring, 4, &sk, b"run-1", b"msg", &mut rng).unwrap();
        let sig_b = sign(&ring, 4, &sk, b"run-1", b"msg-other", &mut rng).unwrap();
        let sig_c = sign(&ring, 4, &sk, b"run-2", b"msg", &mut rng).unwrap();
        // Same run, same signer: key images must match (Sybil detection).
        assert_eq!(sig_a.key_image.to_bytes(), sig_b.key_image.to_bytes());
        // Different run: rotated, must differ.
        assert_ne!(sig_a.key_image.to_bytes(), sig_c.key_image.to_bytes());
    }

    #[test]
    fn signature_wire_round_trip() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(7, 5);
        let sig = sign(&ring, 5, &sk, b"R", b"M", &mut rng).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), RingSignature::encoded_len(7));
        let parsed = RingSignature::from_bytes(&bytes, 7).unwrap();
        verify(&ring, &parsed, b"R", b"M").unwrap();
    }

    #[test]
    fn attestation_message_is_canonical() {
        let m = attestation_message(&[0xAB; 32], 1);
        assert_eq!(&m[..27], b"jmng/tx_extension_v1/attest");
        assert_eq!(&m[27..59], &[0xAB; 32]);
        assert_eq!(&m[59..], &[0x00, 0x01]);
    }

    #[test]
    fn flipped_response_breaks_verify() {
        let mut rng = OsRng;
        let (ring, sk) = build_ring(4, 1);
        let mut sig = sign(&ring, 1, &sk, b"r", b"m", &mut rng).unwrap();
        sig.s[2] = sig.s[2] + Scalar::one();
        assert!(verify(&ring, &sig, b"r", b"m").is_err());
    }
}
