//! Ports of WalletWasabi.Tests/UnitTests/Crypto/{MacTests, CredentialIssuerKeyTests}.cs.
//!
//! These exercise primitive crypto only: MAC equality/verification surfaces,
//! the issuer secret key validation, and the issuer parameters constructor
//! validation.

use nwabisabi::crypto::randomness::{SecureRandom, WabiSabiRandom};
use nwabisabi::crypto::{
    CredentialIssuerParameters, CredentialIssuerSecretKey, GroupElement, Mac, Scalar,
};
use nwabisabi::error::WabiSabiError;

fn generators_g() -> &'static GroupElement {
    nwabisabi::crypto::Generators::g()
}

#[test]
fn mac_rejects_zero_t() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    // Pick any non-infinity attribute.
    let attribute = (&rng.get_scalar() * generators_g()).unwrap();
    let zero_t = Scalar::zero();
    assert!(Mac::compute_mac(&sk, &attribute, &zero_t).is_err());
}

#[test]
fn mac_rejects_infinity_attribute() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let t = rng.get_scalar();
    let inf = GroupElement::infinity();
    assert!(Mac::compute_mac(&sk, &inf, &t).is_err());
}

#[test]
fn mac_can_produce_and_verify() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let attribute = (&rng.get_scalar() * generators_g()).unwrap();
    let t = rng.get_scalar();
    let mac = Mac::compute_mac(&sk, &attribute, &t).unwrap();
    assert!(mac.verify_mac(&sk, &attribute).unwrap());
}

#[test]
fn mac_can_detect_invalid() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let attribute = (&rng.get_scalar() * generators_g()).unwrap();
    let different_attribute = (&rng.get_scalar() * generators_g()).unwrap();
    let t = rng.get_scalar();

    let mac = Mac::compute_mac(&sk, &attribute, &t).unwrap();
    assert!(!mac.verify_mac(&sk, &different_attribute).unwrap());

    let different_t = rng.get_scalar();
    let different_mac = Mac::compute_mac(&sk, &attribute, &different_t).unwrap();
    assert_ne!(mac, different_mac);

    let mac = Mac::compute_mac(&sk, &attribute, &different_t).unwrap();
    let different_sk = CredentialIssuerSecretKey::new(&mut rng);
    assert!(!mac.verify_mac(&different_sk, &attribute).unwrap());
}

#[test]
fn mac_equality_truth_table() {
    // Mirrors C# `MacTests.EqualityTests`: every combination of swapping one
    // of (attribute, sk, t) makes the resulting MAC unequal to the reference.
    let mut rng = SecureRandom::new();

    let right_attr = (&rng.get_scalar() * generators_g()).unwrap();
    let right_sk = CredentialIssuerSecretKey::new(&mut rng);
    let right_t = rng.get_scalar();

    let wrong_attr = (&rng.get_scalar() * generators_g()).unwrap();
    let wrong_sk = CredentialIssuerSecretKey::new(&mut rng);
    let wrong_t = rng.get_scalar();

    let cases: Vec<(&GroupElement, &CredentialIssuerSecretKey, &Scalar, bool)> = vec![
        (&right_attr, &right_sk, &right_t, true),
        (&right_attr, &right_sk, &wrong_t, false),
        (&right_attr, &wrong_sk, &right_t, false),
        (&right_attr, &wrong_sk, &wrong_t, false),
        (&wrong_attr, &right_sk, &right_t, false),
        (&wrong_attr, &right_sk, &wrong_t, false),
        (&wrong_attr, &wrong_sk, &right_t, false),
        (&wrong_attr, &wrong_sk, &wrong_t, false),
    ];

    let reference = Mac::compute_mac(&right_sk, &right_attr, &right_t).unwrap();
    for (attr, sk, t, expected_eq) in cases {
        let candidate = Mac::compute_mac(sk, attr, t).unwrap();
        assert_eq!(reference == candidate, expected_eq);
        assert_eq!(candidate == reference, expected_eq);
    }

    // Reflexivity.
    assert_eq!(reference, reference);
}

#[test]
fn issuer_secret_key_rejects_zero_in_each_field() {
    // Mirrors C# `CredentialIssuerKeyTests.CannotGenerateIssuerSecretKeyWithZero`.
    let one = Scalar::one();
    let zero = Scalar::zero();

    let cases = [
        ("w", zero, one, one, one, one),
        ("wp", one, zero, one, one, one),
        ("x0", one, one, zero, one, one),
        ("x1", one, one, one, zero, one),
        ("ya", one, one, one, one, zero),
    ];

    for (expected_name, w, wp, x0, x1, ya) in cases {
        let err = CredentialIssuerSecretKey::try_from_scalars(w, wp, x0, x1, ya).unwrap_err();
        match err {
            WabiSabiError::ZeroScalar { name } => assert_eq!(name, expected_name),
            other => panic!("unexpected error for {expected_name}: {other:?}"),
        }
    }
}

#[test]
fn issuer_secret_key_accepts_all_nonzero() {
    let one = Scalar::one();
    let two = one + one;
    let three = two + one;
    let four = three + one;
    let five = four + one;
    let sk = CredentialIssuerSecretKey::try_from_scalars(one, two, three, four, five).unwrap();
    let params = sk.compute_parameters().unwrap();
    assert!(!params.cw.is_infinity());
    assert!(!params.i.is_infinity());
}

#[test]
fn issuer_parameters_rejects_infinity() {
    // Mirrors C# `CredentialIssuerKeyTests.GenerateCredentialIssuerParameters`.
    let inf = GroupElement::infinity();
    let g = generators_g().clone();

    let err = CredentialIssuerParameters::try_new(inf.clone(), g.clone()).unwrap_err();
    match err {
        WabiSabiError::PointAtInfinity { name } => assert_eq!(name, "cw"),
        other => panic!("unexpected: {other:?}"),
    }

    let err = CredentialIssuerParameters::try_new(g.clone(), inf).unwrap_err();
    match err {
        WabiSabiError::PointAtInfinity { name } => assert_eq!(name, "i"),
        other => panic!("unexpected: {other:?}"),
    }

    // Both finite: succeeds.
    CredentialIssuerParameters::try_new(g.clone(), g).unwrap();
}
