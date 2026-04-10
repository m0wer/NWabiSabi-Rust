use nwabisabi::crypto::randomness::{SecureRandom, WabiSabiRandom};
use nwabisabi::crypto::{Generators, Scalar};
use nwabisabi::zero_knowledge::Transcript;

#[test]
fn test_simple_equivalence() {
    let protocol = b"test protocol";
    let mut transcript1 = Transcript::new(protocol);
    let mut transcript2 = Transcript::new(protocol);

    // Commit same nonces
    transcript1.commit_public_nonces(&[Generators::g().clone()]);
    transcript2.commit_public_nonces(&[Generators::g().clone()]);

    // Should produce same challenge
    let challenge1 = transcript1.generate_challenge().unwrap();
    let challenge2 = transcript2.generate_challenge().unwrap();

    assert_eq!(challenge1, challenge2);
}

#[test]
fn test_different_protocols_different_challenges() {
    let mut transcript1 = Transcript::new(b"protocol1");
    let mut transcript2 = Transcript::new(b"protocol2");

    let challenge1 = transcript1.generate_challenge().unwrap();
    let challenge2 = transcript2.generate_challenge().unwrap();

    assert_ne!(challenge1, challenge2);
}

#[test]
fn test_complex_equivalence() {
    let protocol = b"test protocol";
    let mut transcript1 = Transcript::new(protocol);
    let mut transcript2 = Transcript::new(protocol);

    transcript1.commit_public_nonces(&[Generators::g().clone()]);
    transcript2.commit_public_nonces(&[Generators::g().clone()]);

    // Multiple rounds should stay in sync
    for _ in 0..32 {
        let challenge1 = transcript1.generate_challenge().unwrap();
        let challenge2 = transcript2.generate_challenge().unwrap();

        assert_eq!(challenge1, challenge2);

        transcript1.commit_public_nonces(&[Generators::g().clone(), Generators::gv().clone()]);
        transcript2.commit_public_nonces(&[Generators::g().clone(), Generators::gv().clone()]);
    }
}

#[test]
fn test_synthetic_nonces_uniqueness() {
    let protocol = b"test TranscriptRng collisions";
    let mut rng = SecureRandom::new();

    let commitment1 = vec![Generators::gx0().clone()];
    let commitment2 = vec![Generators::gx1().clone()];
    let witness1 = vec![rng.get_scalar()];
    let witness2 = vec![rng.get_scalar()];

    let mut transcript1 = Transcript::new(protocol);
    let mut transcript2 = Transcript::new(protocol);
    let mut transcript3 = Transcript::new(protocol);
    let mut transcript4 = Transcript::new(protocol);

    transcript1.commit_public_nonces(&commitment1);
    transcript2.commit_public_nonces(&commitment2);
    transcript3.commit_public_nonces(&commitment2);
    transcript4.commit_public_nonces(&commitment2);

    let mut provider1 =
        transcript1.create_synthetic_secret_nonce_provider(&witness1, &mut rng);
    let mut provider2 =
        transcript2.create_synthetic_secret_nonce_provider(&witness1, &mut rng);
    let mut provider3 =
        transcript3.create_synthetic_secret_nonce_provider(&witness2, &mut rng);
    let mut provider4 =
        transcript4.create_synthetic_secret_nonce_provider(&witness2, &mut rng);

    let nonce1 = provider1.get_scalar().unwrap();
    let nonce2 = provider2.get_scalar().unwrap();
    let nonce3 = provider3.get_scalar().unwrap();
    let nonce4 = provider4.get_scalar().unwrap();

    // All nonces should be different (different commitments or witnesses + random)
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce1, nonce3);
    assert_ne!(nonce1, nonce4);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce2, nonce4);
    assert_ne!(nonce3, nonce4);
}

#[test]
fn test_synthetic_nonces_vector_size() {
    let protocol = b"witness size";
    let mut rng = SecureRandom::new();

    for size in [1, 3, 5, 7] {
        let witness: Vec<Scalar> = (0..size).map(|_| rng.get_scalar()).collect();

        let transcript = Transcript::new(protocol);
        let mut provider = transcript.create_synthetic_secret_nonce_provider(&witness, &mut rng);

        let nonce_vector = provider.get_scalar_vector().unwrap();

        assert_eq!(nonce_vector.len(), size);
    }
}

#[test]
#[should_panic(expected = "secrets cannot be empty")]
fn test_synthetic_nonces_empty_witness_panics() {
    let protocol = b"empty witness not allowed";
    let mut rng = SecureRandom::new();
    let witness: Vec<Scalar> = vec![];

    let transcript = Transcript::new(protocol);
    transcript.create_synthetic_secret_nonce_provider(&witness, &mut rng);
}

#[test]
fn test_challenge_generation_non_zero() {
    let mut transcript = Transcript::new(b"test");

    for _ in 0..100 {
        let challenge = transcript.generate_challenge().unwrap();
        assert!(!challenge.is_zero(), "Challenge should never be zero");
    }
}

#[test]
fn test_sequential_challenges_different() {
    let mut transcript = Transcript::new(b"test");

    let challenge1 = transcript.generate_challenge().unwrap();
    let challenge2 = transcript.generate_challenge().unwrap();
    let challenge3 = transcript.generate_challenge().unwrap();

    // Sequential challenges should be different
    assert_ne!(challenge1, challenge2);
    assert_ne!(challenge2, challenge3);
    assert_ne!(challenge1, challenge3);
}
