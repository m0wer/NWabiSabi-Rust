//! Direct ports of `WalletWasabi.Tests/UnitTests/Crypto/ProofSystemTests.cs`.
//!
//! Covers the high-level statement constructors used by the credential
//! issuance protocol: issuer-parameters proof (MAC), show-credential proof,
//! balance proof, and zero proof.

use nwabisabi::crypto::randomness::{SecureRandom, WabiSabiRandom};
use nwabisabi::crypto::{
    CredentialIssuerSecretKey, Generators, GroupElementVector, Mac, Scalar, ScalarVector,
};
use nwabisabi::zero_knowledge::statements::{
    balance_proof_knowledge, balance_proof_statement, issuer_parameters_knowledge,
    issuer_parameters_statement, pedersen_commitment, show_credential_knowledge,
    show_credential_statement, zero_proof_knowledge, zero_proof_statement,
};
use nwabisabi::zero_knowledge::{Credential, Proof, ProofSystem, Transcript};

/// Convenience: drive a single `Knowledge` through the proof system.
fn prove_one<R: WabiSabiRandom>(
    knowledge: nwabisabi::zero_knowledge::linear_relation::Knowledge,
    rng: &mut R,
) -> Proof {
    let mut t = Transcript::new(b"test");
    let mut proofs = ProofSystem::prove(&mut t, &[knowledge], rng).unwrap();
    proofs.pop().unwrap()
}

fn verify_one(
    statement: nwabisabi::zero_knowledge::linear_relation::Statement,
    proof: &Proof,
) -> bool {
    let mut t = Transcript::new(b"test");
    ProofSystem::verify(&mut t, &[statement], &[proof.clone()]).unwrap_or(false)
}

// =============================================================================
// CanProveAndVerifyMAC
// =============================================================================

/// Coordinator computes a MAC on a blinded amount, proves to the client that
/// the MAC was generated using the coordinator's secret key, and the client
/// verifies the proof.
#[test]
fn can_prove_and_verify_mac() {
    let mut rng = SecureRandom::new();

    // Coordinator key + parameters.
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let iparams = sk.compute_parameters().unwrap();

    // Client builds a blinded attribute Ma = a*G + r*Gh (here we use Gg as Wasabi does).
    let amount = Scalar::from_u64(10_000);
    let r = rng.get_scalar();
    let ma = pedersen_commitment(&amount, &r).unwrap();

    // Coordinator produces MAC + proof of MAC.
    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let knowledge = issuer_parameters_knowledge(&mac, &ma, &sk).unwrap();
    let proof_of_mac = prove_one(knowledge, &mut rng);

    // Client verifies the proof against the public statement.
    let client_statement = issuer_parameters_statement(&iparams, &mac, &ma).unwrap();
    assert!(verify_one(client_statement.clone(), &proof_of_mac));

    // Tamper detection: reverse responses or nonces.
    let mut rev_responses: Vec<Scalar> = proof_of_mac.responses.as_slice().to_vec();
    rev_responses.reverse();
    let corrupted_responses = ScalarVector::new(rev_responses);
    let invalid = Proof {
        public_nonces: proof_of_mac.public_nonces.clone(),
        responses: corrupted_responses,
    };
    assert!(!verify_one(client_statement.clone(), &invalid));

    let mut rev_nonces = proof_of_mac.public_nonces.as_slice().to_vec();
    rev_nonces.reverse();
    let corrupted_nonces = GroupElementVector::new(rev_nonces);
    let invalid = Proof {
        public_nonces: corrupted_nonces,
        responses: proof_of_mac.responses.clone(),
    };
    assert!(!verify_one(client_statement, &invalid));
}

// =============================================================================
// CanProveAndVerifyMacShow
// =============================================================================

/// Client randomizes credential commitments and proves to the coordinator that
/// the underlying MAC is valid (without revealing which credential it is).
#[test]
fn can_prove_and_verify_mac_show() {
    let mut rng = SecureRandom::new();

    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let iparams = sk.compute_parameters().unwrap();

    // Issued credential: Ma uses Gg (the value generator) per WabiSabi.
    let amount: i64 = 10_000;
    let r = rng.get_scalar();
    let ma = pedersen_commitment(&Scalar::from_u64(amount as u64), &r).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let credential = Credential::new(amount, r.clone(), mac.clone()).unwrap();

    // Client randomizes for presentation.
    let z = rng.get_scalar();
    let presentation = credential.present(&z).unwrap();

    let knowledge =
        show_credential_knowledge(&presentation, &z, amount, &r, &t, &iparams).unwrap();
    let proof = prove_one(knowledge, &mut rng);

    // Coordinator computes capital_Z from its secret key and verifies.
    let capital_z = presentation.compute_z(&sk).unwrap();
    let expected = (&z * &iparams.i).unwrap();
    assert_eq!(capital_z, expected);

    let statement = show_credential_statement(&presentation, &capital_z, &iparams);
    assert!(verify_one(statement, &proof));
}

// =============================================================================
// CanProveAndVerifyPresentedBalance
// =============================================================================

/// A presented credential commits to amount `a` with randomness `r` and is
/// re-randomized with `z` to `Ca = z*Ga + a*Gg + r*Gh`. The balance proof
/// must verify against `B = Ca - a*Gg = z*Ga + r*Gh`.
#[test]
fn can_prove_and_verify_presented_balance() {
    let mut rng = SecureRandom::new();

    let a = Scalar::from_u64(10_000);
    let r = rng.get_scalar();
    let z = rng.get_scalar();

    let z_ga = (&z * Generators::ga()).unwrap();
    let a_gg = (&a * Generators::gg()).unwrap();
    let r_gh = (&r * Generators::gh()).unwrap();
    let ca = ((z_ga + a_gg).unwrap() + r_gh).unwrap();

    let knowledge = balance_proof_knowledge(z, r).unwrap();
    let proof = prove_one(knowledge, &mut rng);

    // Valid: B = Ca - a*Gg
    let b_good = (ca.clone() - (&a * Generators::gg()).unwrap()).unwrap();
    assert!(verify_one(balance_proof_statement(b_good), &proof));

    // Invalid: a different shifted commitment.
    let one_gg = (&Scalar::one() * Generators::gg()).unwrap();
    let shifted = ((ca.clone() + one_gg).unwrap() - (&a * Generators::gg()).unwrap()).unwrap();
    assert!(!verify_one(balance_proof_statement(shifted), &proof));

    // Invalid: no subtraction at all.
    assert!(!verify_one(balance_proof_statement(ca), &proof));
}

// =============================================================================
// CanProveAndVerifyRequestedBalance
// =============================================================================

/// Requested attribute `Ma = a*Gg + r*Gh` with amount opened by the client.
/// The balance proof on the requested side is for `B = a*Gg - Ma = -r*Gh`,
/// witness `(0, -r)`.
#[test]
fn can_prove_and_verify_requested_balance() {
    let mut rng = SecureRandom::new();

    let a = Scalar::from_u64(10_000);
    let r = rng.get_scalar();
    let ma = pedersen_commitment(&a, &r).unwrap();

    let knowledge = balance_proof_knowledge(Scalar::zero(), r.negate()).unwrap();
    let proof = prove_one(knowledge, &mut rng);

    let b = ((&a * Generators::gg()).unwrap() - ma.clone()).unwrap();
    assert!(verify_one(balance_proof_statement(b), &proof));

    // Invalid statement: Ma alone is not the balance commitment.
    assert!(!verify_one(balance_proof_statement(ma), &proof));
}

// =============================================================================
// CanProveAndVerifyBalance (Theory)
// =============================================================================

fn balance_case(presented_amount: i64, requested_amount: i64) {
    let mut rng = SecureRandom::new();

    let a = Scalar::from_u64(presented_amount as u64);
    let r = rng.get_scalar();
    let z = rng.get_scalar();
    let ca = {
        let za = (&z * Generators::ga()).unwrap();
        let ag = (&a * Generators::gg()).unwrap();
        let rh = (&r * Generators::gh()).unwrap();
        ((za + ag).unwrap() + rh).unwrap()
    };

    let ap = Scalar::from_u64(requested_amount as u64);
    let rp = rng.get_scalar();
    let ma = pedersen_commitment(&ap, &rp).unwrap();

    // delta = (requested - presented) but as a scalar with appropriate sign.
    let abs_delta = Scalar::from_u64((presented_amount - requested_amount).unsigned_abs());
    let delta = if presented_amount > requested_amount {
        abs_delta.negate()
    } else {
        abs_delta
    };

    let knowledge = balance_proof_knowledge(z, &r + &rp.negate()).unwrap();
    let proof = prove_one(knowledge, &mut rng);

    // Valid balance commitment: B = Ca + delta*Gg - Ma.
    let b = {
        let dg = (&delta * Generators::gg()).unwrap();
        ((ca.clone() + dg).unwrap() - ma.clone()).unwrap()
    };
    assert!(verify_one(balance_proof_statement(b), &proof));

    // Invalid: shift delta by +1.
    let bad = {
        let dg = (&(&delta + &Scalar::one()) * Generators::gg()).unwrap();
        ((ca + dg).unwrap() - ma).unwrap()
    };
    assert!(!verify_one(balance_proof_statement(bad), &proof));
}

#[test]
fn can_prove_and_verify_balance_zero_zero() {
    balance_case(0, 0);
}

#[test]
fn can_prove_and_verify_balance_zero_one() {
    balance_case(0, 1);
}

#[test]
fn can_prove_and_verify_balance_one_zero() {
    balance_case(1, 0);
}

#[test]
fn can_prove_and_verify_balance_one_one() {
    balance_case(1, 1);
}

#[test]
fn can_prove_and_verify_balance_seven_eleven() {
    balance_case(7, 11);
}

#[test]
fn can_prove_and_verify_balance_eleven_seven() {
    balance_case(11, 7);
}

#[test]
fn can_prove_and_verify_balance_10k_zero() {
    balance_case(10_000, 0);
}

#[test]
fn can_prove_and_verify_balance_zero_10k() {
    balance_case(0, 10_000);
}

#[test]
fn can_prove_and_verify_balance_10k_10k() {
    balance_case(10_000, 10_000);
}

#[test]
fn can_prove_and_verify_balance_intmax_intmax() {
    balance_case(i32::MAX as i64, i32::MAX as i64);
}

#[test]
fn can_prove_and_verify_balance_intmax_minus_one_intmax() {
    balance_case(i32::MAX as i64 - 1, i32::MAX as i64);
}

#[test]
fn can_prove_and_verify_balance_intmax_intmax_minus_one() {
    balance_case(i32::MAX as i64, i32::MAX as i64 - 1);
}

// =============================================================================
// CanProveAndVerifyZeroProofs
// =============================================================================

/// Both attributes commit to value 0; prover proves `Ma = r*Gh` for each.
#[test]
fn can_prove_and_verify_zero_proofs() {
    let mut rng = SecureRandom::new();

    let r0 = rng.get_scalar();
    let ma0 = pedersen_commitment(&Scalar::zero(), &r0).unwrap();
    let r1 = rng.get_scalar();
    let ma1 = pedersen_commitment(&Scalar::zero(), &r1).unwrap();

    let knowledge = vec![
        zero_proof_knowledge(ma0.clone(), r0).unwrap(),
        zero_proof_knowledge(ma1.clone(), r1).unwrap(),
    ];

    let mut prover = Transcript::new(&[]);
    let proofs = ProofSystem::prove(&mut prover, &knowledge, &mut rng).unwrap();

    let statements = vec![zero_proof_statement(ma0), zero_proof_statement(ma1)];
    let mut verifier = Transcript::new(&[]);
    assert!(ProofSystem::verify(&mut verifier, &statements, &proofs).unwrap());
}

/// A non-zero attribute must fail the zero proof.
#[test]
fn zero_proof_rejects_nonzero_attribute() {
    let mut rng = SecureRandom::new();
    let r = rng.get_scalar();
    let ma = pedersen_commitment(&Scalar::from_u64(1), &r).unwrap();

    // Proving `Ma = r*Gh` with the wrong r-only witness is impossible because
    // the relation does not hold; constructing knowledge succeeds (bytes wise)
    // but produces a proof that fails verification of the *true* statement.
    let bogus = zero_proof_knowledge(ma.clone(), r).unwrap();
    // soundness assert detects the mismatch
    assert!(bogus.assert_soundness().is_err());
}
