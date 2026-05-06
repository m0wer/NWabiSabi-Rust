use nwabisabi::crypto::issuer_key::CredentialIssuerSecretKey;
use nwabisabi::crypto::randomness::{SecureRandom, WabiSabiRandom};
use nwabisabi::crypto::{Generators, Mac, Scalar};
use nwabisabi::zero_knowledge::Credential;

#[test]
fn test_mac_computation() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    // Create a random attribute (any point)
    let attribute_scalar = rng.get_scalar();
    let attribute = (&attribute_scalar * Generators::g()).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &attribute, &t).unwrap();

    assert!(!mac.t.is_zero());
    assert!(!mac.v.is_infinity());
}

#[test]
fn test_mac_verification_succeeds() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let attribute_scalar = rng.get_scalar();
    let attribute = (&attribute_scalar * Generators::g()).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &attribute, &t).unwrap();

    // Verification should succeed
    assert!(mac.verify_mac(&sk, &attribute).unwrap());
}

#[test]
fn test_mac_verification_fails_wrong_attribute() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let attribute1 = (&rng.get_scalar() * Generators::g()).unwrap();
    let attribute2 = (&rng.get_scalar() * Generators::g()).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &attribute1, &t).unwrap();

    // Verification with different attribute should fail
    assert!(!mac.verify_mac(&sk, &attribute2).unwrap());
}

#[test]
fn test_mac_verification_fails_wrong_key() {
    let mut rng = SecureRandom::new();
    let sk1 = CredentialIssuerSecretKey::new(&mut rng);
    let sk2 = CredentialIssuerSecretKey::new(&mut rng);

    let attribute = (&rng.get_scalar() * Generators::g()).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk1, &attribute, &t).unwrap();

    // Verification with different key should fail
    assert!(!mac.verify_mac(&sk2, &attribute).unwrap());
}

#[test]
fn test_mac_different_t_produces_different_mac() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let attribute = (&rng.get_scalar() * Generators::g()).unwrap();

    let t1 = rng.get_scalar();
    let t2 = rng.get_scalar();

    let mac1 = Mac::compute_mac(&sk, &attribute, &t1).unwrap();
    let mac2 = Mac::compute_mac(&sk, &attribute, &t2).unwrap();

    assert_ne!(mac1, mac2);
}

#[test]
fn test_mac_u_generation_deterministic() {
    let t = Scalar::one();

    let u1 = Mac::generate_u(&t);
    let u2 = Mac::generate_u(&t);

    assert_eq!(u1, u2);
}

#[test]
fn test_credential_creation() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let value = 10_000i64;
    let randomness = rng.get_scalar();

    // Create attribute Ma (Pedersen commitment)
    let value_scalar = Scalar::from_u64(value as u64);

    let ma = ((value_scalar * Generators::gg()).unwrap()
        + (randomness * Generators::gh()).unwrap())
    .unwrap();

    // Generate MAC
    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    // Create credential
    let credential = Credential::new(value, randomness, mac).unwrap();

    assert_eq!(credential.value(), 10_000);
}

#[test]
fn test_credential_presentation() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let value = 50_000i64;
    let randomness = rng.get_scalar();

    let value_scalar = Scalar::from_u64(value as u64);

    let ma = ((value_scalar * Generators::gg()).unwrap()
        + (randomness * Generators::gh()).unwrap())
    .unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let credential = Credential::new(value, randomness, mac).unwrap();

    // Randomize for presentation
    let z = rng.get_scalar();
    let presentation = credential.present(&z).unwrap();

    // All components should be non-infinity
    assert!(!presentation.ca().is_infinity());
    assert!(!presentation.cx0().is_infinity());
    assert!(!presentation.cx1().is_infinity());
    assert!(!presentation.cv().is_infinity());
    assert!(!presentation.s().is_infinity());
}

#[test]
fn test_credential_presentation_compute_z() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let value = 25_000i64;
    let randomness = rng.get_scalar();

    let value_scalar = Scalar::from_u64(value as u64);

    let ma = ((value_scalar * Generators::gg()).unwrap()
        + (randomness * Generators::gh()).unwrap())
    .unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let credential = Credential::new(value, randomness, mac).unwrap();

    // Present with randomization
    let z = rng.get_scalar();
    let presentation = credential.present(&z).unwrap();

    // Compute Z
    let capital_z = presentation.compute_z(&sk).unwrap();

    // Z should equal z * I (where I = ya*Ga)
    let params = sk.compute_parameters().unwrap();
    let expected_z = (&z * &params.i).unwrap();

    assert_eq!(capital_z, expected_z);
}

#[test]
fn test_different_randomizations_produce_different_presentations() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let value = 75_000i64;
    let randomness = rng.get_scalar();

    let value_scalar = Scalar::from_u64(value as u64);

    let ma = ((value_scalar * Generators::gg()).unwrap()
        + (randomness * Generators::gh()).unwrap())
    .unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let credential = Credential::new(value, randomness, mac).unwrap();

    // Present with two different randomization factors
    let z1 = rng.get_scalar();
    let z2 = rng.get_scalar();

    let presentation1 = credential.present(&z1).unwrap();
    let presentation2 = credential.present(&z2).unwrap();

    // Different randomizations should produce different presentations
    assert_ne!(presentation1.ca(), presentation2.ca());
    assert_ne!(presentation1.cx0(), presentation2.cx0());
    assert_ne!(presentation1.cx1(), presentation2.cx1());
    assert_ne!(presentation1.cv(), presentation2.cv());

    // Serial number should be the same (deterministic from randomness)
    assert_eq!(presentation1.s(), presentation2.s());
}

#[test]
fn test_credential_with_zero_amount() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let value = 0i64;
    let randomness = rng.get_scalar();

    let value_scalar = Scalar::zero();
    let ma = (randomness * Generators::gh()).unwrap();

    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &ma, &t).unwrap();

    let credential = Credential::new(value, randomness, mac).unwrap();

    assert_eq!(credential.value(), 0);

    // Should be able to present zero-amount credential
    let z = rng.get_scalar();
    let presentation = credential.present(&z).unwrap();

    assert!(!presentation.ca().is_infinity());
}

#[test]
fn test_mac_equality() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);

    let attribute = (&rng.get_scalar() * Generators::g()).unwrap();
    let t = rng.get_scalar();

    let mac1 = Mac::compute_mac(&sk, &attribute, &t).unwrap();
    let mac2 = Mac::compute_mac(&sk, &attribute, &t).unwrap();

    // Same inputs should produce same MAC
    assert_eq!(mac1, mac2);
}
