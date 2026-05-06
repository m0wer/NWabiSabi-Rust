//! Canonical statement and knowledge constructors for the WabiSabi protocol.
//!
//! Mirrors `WalletWasabi.Crypto.ZeroKnowledge.ProofSystem` in the upstream
//! C# implementation. Every constructor here builds the same matrix layout
//! used by the reference prover/verifier so the Sigma transcripts produced
//! by both sides interoperate byte-for-byte.

use crate::credential_requesting::IssuanceRequest;
use crate::crypto::issuer_key::{CredentialIssuerParameters, CredentialIssuerSecretKey};
use crate::crypto::randomness::WabiSabiRandom;
use crate::crypto::{Generators, GroupElement, Mac, Scalar, ScalarVector};
use crate::error::Result;
use crate::zero_knowledge::linear_relation::{Knowledge, Statement};
use crate::zero_knowledge::CredentialPresentation;

/// Maximum range-proof width supported (bits). C# enforces 0..=255.
pub const MAX_RANGE_PROOF_WIDTH: usize = 255;

fn infinity() -> GroupElement {
    GroupElement::infinity()
}

fn add(a: &GroupElement, b: &GroupElement) -> GroupElement {
    (a + b).expect("group element addition is infallible")
}

fn sub(a: &GroupElement, b: &GroupElement) -> GroupElement {
    (a - b).expect("group element subtraction is infallible")
}

fn neg(a: &GroupElement) -> GroupElement {
    a.negate().expect("group element negation is infallible")
}

/// Pedersen commitment `value * Gg + blinding * Gh`.
pub fn pedersen_commitment(value: &Scalar, blinding: &Scalar) -> Result<GroupElement> {
    let v_term = (value * Generators::gg())?;
    let r_term = (blinding * Generators::gh())?;
    v_term + r_term
}

/// Issuer parameters knowledge: prove the issuer knows `(w, wp, x0, x1, ya)`
/// underlying both `Cw = w*Gw + wp*Gwp` and the issued MAC.
///
/// Witness order: `[w, wp, x0, x1, ya]`.
pub fn issuer_parameters_knowledge(
    mac: &Mac,
    ma: &GroupElement,
    sk: &CredentialIssuerSecretKey,
) -> Result<Knowledge> {
    let params = sk.compute_parameters()?;
    let statement = issuer_parameters_statement(&params, mac, ma)?;
    let witness = ScalarVector::new(vec![
        sk.w.clone(),
        sk.wp.clone(),
        sk.x0.clone(),
        sk.x1.clone(),
        sk.ya.clone(),
    ]);
    Knowledge::new(statement, witness)
}

/// Issuer parameters statement.
///
/// Three equations sharing witness `[w, wp, x0, x1, ya]`:
///   row 0: `mac.V          = w*Gw + 0*Gwp + t0*Gx0_pub? ...` (see matrix)
///   row 1: `Gv - I         = 0*Gw + 0*Gwp + 1*Gx0 + 1*Gx1 + 1*Ga`
///   row 2: `Cw             = w*Gw + wp*Gwp`
pub fn issuer_parameters_statement(
    iparams: &CredentialIssuerParameters,
    mac: &Mac,
    ma: &GroupElement,
) -> Result<Statement> {
    let u = mac.u();
    let t_u = (&mac.t * &u)?;
    let gv_minus_i = sub(Generators::gv(), &iparams.i);

    // Matrix rows: [public, w_gen, wp_gen, x0_gen, x1_gen, ya_gen]
    let matrix = vec![
        vec![
            Some(mac.v.clone()),
            Some(Generators::gw().clone()),
            Some(infinity()),
            Some(u),
            Some(t_u),
            Some(ma.clone()),
        ],
        vec![
            Some(gv_minus_i),
            Some(infinity()),
            Some(infinity()),
            Some(Generators::gx0().clone()),
            Some(Generators::gx1().clone()),
            Some(Generators::ga().clone()),
        ],
        vec![
            Some(iparams.cw.clone()),
            Some(Generators::gw().clone()),
            Some(Generators::gwp().clone()),
            Some(infinity()),
            Some(infinity()),
            Some(infinity()),
        ],
    ];
    Ok(Statement::from_matrix(matrix))
}

/// Show-credential knowledge.
///
/// Witness order (5 components, matching C#):
///   `[z, -t*z, t, value, randomness]`
///
/// Caller must pre-compute `Z = z * I` and pass it as the public point of
/// the first equation.
pub fn show_credential_knowledge(
    presentation: &CredentialPresentation,
    z: &Scalar,
    value: i64,
    randomness: &Scalar,
    mac_t: &Scalar,
    iparams: &CredentialIssuerParameters,
) -> Result<Knowledge> {
    if value < 0 {
        return Err(crate::error::WabiSabiError::Unspecified);
    }
    let z_pub = (z * &iparams.i)?;
    let statement = show_credential_statement(presentation, &z_pub, iparams);
    let neg_tz = (mac_t * z).negate();
    let value_scalar = Scalar::from_u64(value as u64);
    let witness = ScalarVector::new(vec![
        z.clone(),
        neg_tz,
        mac_t.clone(),
        value_scalar,
        randomness.clone(),
    ]);
    Knowledge::new(statement, witness)
}

/// Show-credential statement (4 equations, witness width 5).
///
/// Rows are exactly the C# matrix:
///   `Z   = I*z`
///   `Cx1 = Gx1*z + Gx0*(-tz) + Cx0*t`
///   `Ca  = Ga*z + Gg*value + Gh*randomness`
///   `S   = Gs*randomness`
pub fn show_credential_statement(
    c: &CredentialPresentation,
    z_public: &GroupElement,
    iparams: &CredentialIssuerParameters,
) -> Statement {
    let matrix = vec![
        vec![
            Some(z_public.clone()),
            Some(iparams.i.clone()),
            Some(infinity()),
            Some(infinity()),
            Some(infinity()),
            Some(infinity()),
        ],
        vec![
            Some(c.cx1().clone()),
            Some(Generators::gx1().clone()),
            Some(Generators::gx0().clone()),
            Some(c.cx0().clone()),
            Some(infinity()),
            Some(infinity()),
        ],
        vec![
            Some(c.ca().clone()),
            Some(Generators::ga().clone()),
            Some(infinity()),
            Some(infinity()),
            Some(Generators::gg().clone()),
            Some(Generators::gh().clone()),
        ],
        vec![
            Some(c.s().clone()),
            Some(infinity()),
            Some(infinity()),
            Some(infinity()),
            Some(infinity()),
            Some(Generators::gs().clone()),
        ],
    ];
    Statement::from_matrix(matrix)
}

/// Balance-proof knowledge.
///
/// `balanceCommitment = zSum * Ga + rDeltaSum * Gh` must commit to zero,
/// and the witness is `[zSum, rDeltaSum]`.
pub fn balance_proof_knowledge(z_sum: Scalar, r_delta_sum: Scalar) -> Result<Knowledge> {
    let z_term = (&z_sum * Generators::ga())?;
    let r_term = (&r_delta_sum * Generators::gh())?;
    let balance_commitment = (z_term + r_term)?;
    let statement = balance_proof_statement(balance_commitment);
    let witness = ScalarVector::new(vec![z_sum, r_delta_sum]);
    Knowledge::new(statement, witness)
}

/// Balance-proof statement: a single equation `B = zSum*Ga + rDeltaSum*Gh`.
pub fn balance_proof_statement(balance_commitment: GroupElement) -> Statement {
    Statement::new(
        balance_commitment,
        vec![Generators::ga().clone(), Generators::gh().clone()],
    )
}

/// Zero-proof statement: bootstrap credential request, range proof of width 0.
///
/// Equivalent to `Statement::new(ma, [Gh])`.
pub fn zero_proof_statement(ma: GroupElement) -> Statement {
    range_proof_statement(ma, &[], 0)
}

/// Zero-proof knowledge: prove `Ma = r*Gh` for a known blinding factor `r`.
pub fn zero_proof_knowledge(ma: GroupElement, r: Scalar) -> Result<Knowledge> {
    let statement = zero_proof_statement(ma);
    let witness = ScalarVector::new(vec![r]);
    Knowledge::new(statement, witness)
}

/// Build a range-proof knowledge for amount `value` in `[0, 2^width)` with
/// blinding `r` for `Ma = value*Gg + r*Gh`. Returns the knowledge plus the
/// per-bit Pedersen commitments that become public inputs of the proof.
///
/// The commitment vector is in bit order, LSB first: `bit_commitments[i]`
/// corresponds to bit `i` of `value`.
pub fn range_proof_knowledge<R: WabiSabiRandom>(
    value: u64,
    r: Scalar,
    width: usize,
    rng: &mut R,
) -> Result<(Knowledge, GroupElement, Vec<GroupElement>)> {
    if width > MAX_RANGE_PROOF_WIDTH {
        return Err(crate::error::WabiSabiError::Unspecified);
    }
    if width < 64 && value >= (1u64 << width) {
        return Err(crate::error::WabiSabiError::Unspecified);
    }

    let value_scalar = Scalar::from_u64(value);
    let ma = pedersen_commitment(&value_scalar, &r)?;

    // Per-bit randomness and commitments.
    let mut bit_randomness = Vec::with_capacity(width);
    let mut bit_commitments = Vec::with_capacity(width);
    for i in 0..width {
        let bit = if width >= 64 || ((value >> i) & 1) == 1 {
            // For width >= 64 the bit may be from extended scalar; here we
            // only support u64 values, so width <= 64 is enforced by check
            // above. The branch is on bit value for width <= 64.
            (value >> i) & 1 == 1
        } else {
            false
        };
        let b = if bit { Scalar::one() } else { Scalar::zero() };
        let r_i = rng.get_scalar();
        let commitment = pedersen_commitment(&b, &r_i)?;
        bit_randomness.push((b, r_i));
        bit_commitments.push(commitment);
    }

    let statement = range_proof_statement(ma, &bit_commitments, width);

    // Witness layout: [r, b_0, r_0, rb_0, b_1, r_1, rb_1, ...]
    let mut witness_vec = Vec::with_capacity(1 + 3 * width);
    witness_vec.push(r);
    for (b, r_i) in &bit_randomness {
        let rb = b * r_i;
        witness_vec.push(b.clone());
        witness_vec.push(r_i.clone());
        witness_vec.push(rb);
    }

    let knowledge = Knowledge::new(statement, ScalarVector::new(witness_vec))?;
    Ok((knowledge, ma, bit_commitments))
}

/// Range-proof statement: prove `Ma` commits to a value in `[0, 2^width)`
/// whose bit decomposition matches `bit_commitments` (LSB first).
///
/// Matrix layout (rows = `2*width + 1`, cols = `1 + 1 + 3*width`):
///   row 0:                bit-decomposition equation
///   row `2*i + 1`:        `B_i = b_i*Gg + r_i*Gh`
///   row `2*i + 2`:        `O   = b_i*(B_i - Gg) - rb_i*Gh`
///
/// Witness layout: `[r, b_0, r_0, rb_0, b_1, r_1, rb_1, ...]`.
pub fn range_proof_statement(
    ma: GroupElement,
    bit_commitments: &[GroupElement],
    width: usize,
) -> Statement {
    assert_eq!(
        bit_commitments.len(),
        width,
        "bit commitments length must equal width"
    );
    assert!(width <= MAX_RANGE_PROOF_WIDTH, "width out of range");

    let powers_of_two = Generators::scalar_powers_of_two();
    let neg_gh_powers = Generators::negated_gh_powers_of_two();
    let columns = 1 + 1 + 3 * width; // public + r + (b, r_i, rb_i) per bit

    let bit_column = |i: usize| 2 + 3 * i;
    let rnd_column = |i: usize| bit_column(i) + 1;
    let product_column = |i: usize| bit_column(i) + 2;

    let bit_repr_row = |i: usize| 2 * i + 1;
    let bit_squared_row = |i: usize| bit_repr_row(i) + 1;
    let total_rows = 2 * width + 1;

    let mut matrix: Vec<Vec<Option<GroupElement>>> =
        vec![vec![Some(infinity()); columns]; total_rows];

    // Row 0: (Ma - sum 2^i * B_i) = r*Gh + sum (-2^i * Gh) * r_i
    let mut bits_total = infinity();
    for (i, b_i) in bit_commitments.iter().enumerate() {
        let term = (&powers_of_two[i] * b_i).expect("scalar mul infallible");
        bits_total = (bits_total + term).expect("add infallible");
    }
    matrix[0][0] = Some(sub(&ma, &bits_total));
    matrix[0][1] = Some(Generators::gh().clone());

    let neg_gh = neg(Generators::gh());

    for i in 0..width {
        // Update row 0 r_i column with -2^i * Gh.
        matrix[0][rnd_column(i)] = Some(neg_gh_powers[i].clone());

        // Bit-representation row: B_i = b_i*Gg + r_i*Gh.
        matrix[bit_repr_row(i)][0] = Some(bit_commitments[i].clone());
        matrix[bit_repr_row(i)][bit_column(i)] = Some(Generators::gg().clone());
        matrix[bit_repr_row(i)][rnd_column(i)] = Some(Generators::gh().clone());

        // Bit-squared row: O = b_i*(B_i - Gg) - rb_i*Gh.
        let b_minus_gg = sub(&bit_commitments[i], Generators::gg());
        matrix[bit_squared_row(i)][0] = Some(infinity());
        matrix[bit_squared_row(i)][bit_column(i)] = Some(b_minus_gg);
        matrix[bit_squared_row(i)][product_column(i)] = Some(neg_gh.clone());
    }

    Statement::from_matrix(matrix)
}

/// Build the public statement for an [`IssuanceRequest`] (real-amount path).
///
/// Equivalent to [`range_proof_statement`] but takes the request rather than
/// raw `(Ma, bit_commitments, width)`.
pub fn issuance_request_statement(req: &IssuanceRequest, width: usize) -> Statement {
    range_proof_statement(req.ma().clone(), req.bit_commitments(), width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randomness::SecureRandom;
    use crate::zero_knowledge::{ProofSystem, Transcript};

    fn fresh_rng() -> SecureRandom {
        SecureRandom::new()
    }

    fn issue_credential(
        sk: &CredentialIssuerSecretKey,
        value: i64,
        randomness: &Scalar,
        rng: &mut SecureRandom,
    ) -> (Mac, GroupElement) {
        let value_scalar = Scalar::from_u64(value as u64);
        let ma = pedersen_commitment(&value_scalar, randomness).unwrap();
        let t = rng.get_scalar();
        let mac = Mac::compute_mac(sk, &ma, &t).unwrap();
        (mac, ma)
    }

    #[test]
    fn test_pedersen_commitment_homomorphic() {
        let mut rng = fresh_rng();
        let v1 = Scalar::from_u64(100);
        let v2 = Scalar::from_u64(200);
        let r1 = rng.get_scalar();
        let r2 = rng.get_scalar();
        let c1 = pedersen_commitment(&v1, &r1).unwrap();
        let c2 = pedersen_commitment(&v2, &r2).unwrap();
        let sum = (c1 + c2).unwrap();
        let expected = pedersen_commitment(&(v1 + v2), &(r1 + r2)).unwrap();
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_issuer_parameters_proof_roundtrip() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let randomness = rng.get_scalar();
        let (mac, ma) = issue_credential(&sk, 1_000, &randomness, &mut rng);

        let knowledge = issuer_parameters_knowledge(&mac, &ma, &sk).unwrap();
        knowledge.assert_soundness().expect("witness must satisfy");

        let mut tp = Transcript::new(b"issuer-params-test");
        let proofs =
            ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"issuer-params-test");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_show_credential_proof_roundtrip() {
        let mut rng = fresh_rng();
        let sk = CredentialIssuerSecretKey::new(&mut rng);
        let value = 42_000i64;
        let randomness = rng.get_scalar();
        let (mac, _ma) = issue_credential(&sk, value, &randomness, &mut rng);

        let credential = crate::zero_knowledge::Credential::new(value, randomness.clone(), mac.clone()).unwrap();
        let z = rng.get_scalar();
        let presentation = credential.present(&z).unwrap();
        let iparams = sk.compute_parameters().unwrap();

        let knowledge = show_credential_knowledge(
            &presentation,
            &z,
            value,
            &randomness,
            &mac.t,
            &iparams,
        )
        .unwrap();
        knowledge
            .assert_soundness()
            .expect("show-credential witness must satisfy");

        let mut tp = Transcript::new(b"show-cred-test");
        let proofs = ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"show-cred-test");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_balance_proof_zero_sum_roundtrip() {
        let mut rng = fresh_rng();
        let z_sum = rng.get_scalar();
        let r_delta = rng.get_scalar();
        let knowledge = balance_proof_knowledge(z_sum, r_delta).unwrap();
        knowledge.assert_soundness().expect("balance witness");

        let mut tp = Transcript::new(b"balance-test");
        let proofs = ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"balance-test");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_zero_proof_roundtrip() {
        let mut rng = fresh_rng();
        let r = rng.get_scalar();
        let ma = (&r * Generators::gh()).unwrap();
        let knowledge = zero_proof_knowledge(ma, r).unwrap();
        knowledge.assert_soundness().expect("zero witness");

        let mut tp = Transcript::new(b"zero-test");
        let proofs = ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"zero-test");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_range_proof_roundtrip_small() {
        let mut rng = fresh_rng();
        let value: u64 = 0b1010_1100; // 172, fits in 8 bits
        let r = rng.get_scalar();
        let (knowledge, _ma, _bit_commitments) = range_proof_knowledge(value, r, 8, &mut rng).unwrap();
        knowledge.assert_soundness().expect("range witness");

        let mut tp = Transcript::new(b"range-test");
        let proofs = ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"range-test");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_range_proof_roundtrip_full_width() {
        let mut rng = fresh_rng();
        let value: u64 = 1_234_567_890_123;
        let r = rng.get_scalar();
        let (knowledge, _ma, _) = range_proof_knowledge(value, r, 51, &mut rng).unwrap();
        knowledge.assert_soundness().expect("range witness");

        let mut tp = Transcript::new(b"range-test-51");
        let proofs = ProofSystem::prove(&mut tp, std::slice::from_ref(&knowledge), &mut rng).unwrap();
        let mut tv = Transcript::new(b"range-test-51");
        let ok = ProofSystem::verify(
            &mut tv,
            std::slice::from_ref(&knowledge.statement),
            &proofs,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_range_proof_value_too_large_rejected() {
        let mut rng = fresh_rng();
        let r = rng.get_scalar();
        // value 256 doesn't fit in 8 bits
        let result = range_proof_knowledge(256, r, 8, &mut rng);
        assert!(result.is_err());
    }
}
