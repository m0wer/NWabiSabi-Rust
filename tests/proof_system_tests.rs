use nwabisabi::crypto::randomness::{SecureRandom, WabiSabiRandom};
use nwabisabi::crypto::{Generators, Scalar, ScalarVector};
use nwabisabi::zero_knowledge::linear_relation::{Knowledge, Statement};
use nwabisabi::zero_knowledge::{ProofSystem, Transcript};

#[test]
fn test_simple_knowledge_of_discrete_log() {
    let mut rng = SecureRandom::new();

    // Prove knowledge of x such that P = x*G
    let g = Generators::g().clone();
    let x = rng.get_scalar();
    let p = (&x * &g).unwrap();

    let statement = Statement::new(p, vec![g]);
    let witness = ScalarVector::new(vec![x]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Prover generates proof
    let mut prover_transcript = Transcript::new(b"test KORL");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    assert_eq!(proofs.len(), 1);

    // Verifier checks proof
    let mut verifier_transcript = Transcript::new(b"test KORL");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(valid);
}

#[test]
fn test_knowledge_of_representation() {
    let mut rng = SecureRandom::new();

    // Prove knowledge of (x1, x2) such that P = x1*G + x2*H
    let g = Generators::g().clone();
    let h = Generators::gh().clone();

    let x1 = rng.get_scalar();
    let x2 = rng.get_scalar();

    let p1 = (&x1 * &g).unwrap();
    let p2 = (&x2 * &h).unwrap();
    let p = (p1 + p2).unwrap();

    let statement = Statement::new(p, vec![g, h]);
    let witness = ScalarVector::new(vec![x1, x2]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"test KOR");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Verify proof
    let mut verifier_transcript = Transcript::new(b"test KOR");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(valid);
}

#[test]
fn test_multiple_equations_same_witness() {
    let mut rng = SecureRandom::new();

    // Prove knowledge of (x1, x2) that satisfies two equations:
    // P1 = x1*G + x2*H
    // P2 = x1*Gg + x2*Gh
    let g = Generators::g().clone();
    let h = Generators::gh().clone();
    let gg = Generators::gg().clone();
    let gh = Generators::gh().clone();

    let x1 = rng.get_scalar();
    let x2 = rng.get_scalar();

    // First equation
    let p1 = ((&x1 * &g).unwrap() + (&x2 * &h).unwrap()).unwrap();

    // Second equation (same witness, different generators)
    let p2 = ((&x1 * &gg).unwrap() + (&x2 * &gh).unwrap()).unwrap();

    let matrix = vec![
        vec![Some(p1), Some(g), Some(h)],
        vec![Some(p2), Some(gg), Some(gh)],
    ];

    let statement = Statement::from_matrix(matrix);
    let witness = ScalarVector::new(vec![x1, x2]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"test multi");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Verify proof
    let mut verifier_transcript = Transcript::new(b"test multi");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(valid);
}

#[test]
fn test_compound_proof() {
    let mut rng = SecureRandom::new();

    // Create two independent knowledge statements
    let g = Generators::g().clone();
    let h = Generators::gh().clone();

    // First knowledge: P1 = x1*G
    let x1 = rng.get_scalar();
    let p1 = (&x1 * &g).unwrap();
    let statement1 = Statement::new(p1, vec![g.clone()]);
    let witness1 = ScalarVector::new(vec![x1]);
    let knowledge1 = Knowledge::new(statement1.clone(), witness1).unwrap();

    // Second knowledge: P2 = x2*H
    let x2 = rng.get_scalar();
    let p2 = (&x2 * &h).unwrap();
    let statement2 = Statement::new(p2, vec![h]);
    let witness2 = ScalarVector::new(vec![x2]);
    let knowledge2 = Knowledge::new(statement2.clone(), witness2).unwrap();

    // Generate compound proof
    let mut prover_transcript = Transcript::new(b"test compound");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge1, knowledge2], &mut rng).unwrap();

    assert_eq!(proofs.len(), 2);

    // Verify compound proof
    let mut verifier_transcript = Transcript::new(b"test compound");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement1, statement2], &proofs).unwrap();

    assert!(valid);
}

#[test]
fn test_tampered_response_fails() {
    let mut rng = SecureRandom::new();

    let g = Generators::g().clone();
    let x = rng.get_scalar();
    let p = (&x * &g).unwrap();

    let statement = Statement::new(p, vec![g]);
    let witness = ScalarVector::new(vec![x]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"test");
    let mut proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Tamper with response
    let tampered = rng.get_scalar();
    proofs[0].responses = ScalarVector::new(vec![tampered]);

    // Verification should fail
    let mut verifier_transcript = Transcript::new(b"test");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(!valid);
}

#[test]
fn test_tampered_nonce_fails() {
    let mut rng = SecureRandom::new();

    let g = Generators::g().clone();
    let x = rng.get_scalar();
    let p = (&x * &g).unwrap();

    let statement = Statement::new(p, vec![g.clone()]);
    let witness = ScalarVector::new(vec![x]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"test");
    let mut proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Tamper with public nonce
    let tampered_nonce = (&rng.get_scalar() * &g).unwrap();
    proofs[0].public_nonces = nwabisabi::crypto::GroupElementVector::new(vec![tampered_nonce]);

    // Verification should fail
    let mut verifier_transcript = Transcript::new(b"test");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(!valid);
}

#[test]
fn test_wrong_statement_fails() {
    let mut rng = SecureRandom::new();

    let g = Generators::g().clone();
    let x = rng.get_scalar();
    let p = (&x * &g).unwrap();

    let statement = Statement::new(p, vec![g.clone()]);
    let witness = ScalarVector::new(vec![x]);
    let knowledge = Knowledge::new(statement, witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"test");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Try to verify with wrong statement (different public point)
    let wrong_x = rng.get_scalar();
    let wrong_p = (&wrong_x * &g).unwrap();
    let wrong_statement = Statement::new(wrong_p, vec![g]);

    let mut verifier_transcript = Transcript::new(b"test");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[wrong_statement], &proofs).unwrap();

    assert!(!valid);
}

#[test]
fn test_mismatched_transcript_fails() {
    let mut rng = SecureRandom::new();

    let g = Generators::g().clone();
    let x = rng.get_scalar();
    let p = (&x * &g).unwrap();

    let statement = Statement::new(p, vec![g]);
    let witness = ScalarVector::new(vec![x]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof with one protocol label
    let mut prover_transcript = Transcript::new(b"protocol A");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Try to verify with different protocol label
    let mut verifier_transcript = Transcript::new(b"protocol B");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(!valid);
}

#[test]
fn test_pedersen_commitment_proof() {
    let mut rng = SecureRandom::new();

    // Prove knowledge of (value, randomness) in commitment C = value*Gg + randomness*Gh
    let gg = Generators::gg().clone();
    let gh = Generators::gh().clone();

    let value = Scalar::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 16]).unwrap(); // 10000
    let randomness = rng.get_scalar();

    let commitment = ((&value * &gg).unwrap() + (&randomness * &gh).unwrap()).unwrap();

    let statement = Statement::new(commitment, vec![gg, gh]);
    let witness = ScalarVector::new(vec![value, randomness]);
    let knowledge = Knowledge::new(statement.clone(), witness).unwrap();

    // Generate proof
    let mut prover_transcript = Transcript::new(b"pedersen");
    let proofs = ProofSystem::prove(&mut prover_transcript, &[knowledge], &mut rng).unwrap();

    // Verify proof
    let mut verifier_transcript = Transcript::new(b"pedersen");
    let valid = ProofSystem::verify(&mut verifier_transcript, &[statement], &proofs).unwrap();

    assert!(valid);
}
