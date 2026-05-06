//! End-to-end round trips for the WabiSabi credential protocol.
//!
//! The scenarios are ports of WalletWasabi's
//! `WalletWasabi.Tests/UnitTests/WabiSabi/CredentialTests.cs` (the dormant
//! `#if false` block plus the active range-proof-width sanity check) and the
//! invalid-request paths from the same file. They guarantee the Rust port
//! matches the canonical C# semantics for: zero issuance, real issuance,
//! splitting, reissuance with delta=0, range-proof-width selection, and the
//! issuer's input-validation error codes.

use nwabisabi::credential_requesting::{CredentialsRequest, IssuanceRequest, RealCredentialsRequest};
use nwabisabi::crypto::randomness::SecureRandom;
use nwabisabi::crypto::{CredentialIssuerSecretKey, GroupElement};
use nwabisabi::error::WabiSabiError;
use nwabisabi::{CredentialIssuer, WabiSabiClient};

const CREDENTIAL_NUMBER: usize = 2;

fn fresh_pair(max_amount: i64) -> (WabiSabiClient, CredentialIssuer, SecureRandom) {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let params = sk.compute_parameters().unwrap();
    let issuer = CredentialIssuer::new(sk, 0).unwrap();
    let issuer = if max_amount > 0 { issuer.with_max_amount(max_amount) } else { issuer };
    let client = WabiSabiClient::new(params);
    let client = if max_amount > 0 { client.with_max_amount(max_amount) } else { client };
    (client, issuer, rng)
}

#[test]
fn zero_then_real_round_trip() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let zero_creds = client.handle_response(&zero_resp, zero_validation).unwrap();
    assert_eq!(zero_creds.len(), CREDENTIAL_NUMBER);
    for c in &zero_creds {
        assert_eq!(c.value(), 0);
    }

    let amounts = [100u64, 250u64];
    let (real_req, real_validation) =
        client.create_request(&amounts, zero_creds, &mut rng).unwrap();
    assert_eq!(real_req.delta(), 350);
    assert_eq!(real_req.presented().len(), CREDENTIAL_NUMBER);
    assert_eq!(real_req.requested().len(), CREDENTIAL_NUMBER);

    let real_resp = issuer.handle_request(&real_req, &mut rng).unwrap();
    let real_creds = client.handle_response(&real_resp, real_validation).unwrap();
    assert_eq!(real_creds.len(), CREDENTIAL_NUMBER);
    let mut values: Vec<i64> = real_creds.iter().map(|c| c.value()).collect();
    values.sort();
    assert_eq!(values, vec![100, 250]);

    assert_eq!(issuer.balance(), 350);
}

/// Port of `CredentialTests.CredentialIssuance`: full lifecycle with a
/// reissuance step at delta=0, exercising the path where presented + requested
/// values cancel out.
#[test]
fn credential_issuance_full_lifecycle() {
    let (client, issuer, mut rng) = fresh_pair(0);

    // Bootstrap: zero-value credentials.
    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    assert!(zero_req.presented().is_empty());
    assert_eq!(zero_req.requested().len(), CREDENTIAL_NUMBER);
    for r in zero_req.requested() {
        assert!(r.bit_commitments().is_empty());
    }
    assert_eq!(zero_req.delta(), 0);
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let zero_creds = client.handle_response(&zero_resp, zero_validation).unwrap();
    assert_eq!(zero_creds.len(), CREDENTIAL_NUMBER);

    // Real issuance: 1 credential of 100_000_000 + zero-padding (we use 2
    // credentials by design, so issue [100_000_000, 0]).
    let amounts = [100_000_000u64, 0u64];
    let (real_req, real_validation) =
        client.create_request(&amounts, zero_creds, &mut rng).unwrap();
    assert_eq!(real_req.delta(), 100_000_000);
    for r in real_req.requested() {
        assert!(!r.bit_commitments().is_empty());
    }
    let real_resp = issuer.handle_request(&real_req, &mut rng).unwrap();
    let real_creds = client.handle_response(&real_resp, real_validation).unwrap();
    assert_eq!(real_creds.len(), CREDENTIAL_NUMBER);
    let mut values: Vec<i64> = real_creds.iter().map(|c| c.value()).collect();
    values.sort();
    assert_eq!(values, vec![0, 100_000_000]);
    assert_eq!(issuer.balance(), 100_000_000);

    // Reissuance: split 100_000_000 + 0 into 50_000_000 + 50_000_000.
    let split_amounts = [50_000_000u64, 50_000_000u64];
    let (split_req, split_validation) =
        client.create_request(&split_amounts, real_creds, &mut rng).unwrap();
    assert_eq!(split_req.delta(), 0);
    let split_resp = issuer.handle_request(&split_req, &mut rng).unwrap();
    let split_creds = client.handle_response(&split_resp, split_validation).unwrap();
    let mut values: Vec<i64> = split_creds.iter().map(|c| c.value()).collect();
    values.sort();
    assert_eq!(values, vec![50_000_000, 50_000_000]);
    assert_eq!(issuer.balance(), 100_000_000); // unchanged
}

/// Port of `CredentialTests.InvalidCredentialRequests`: tampered requests must
/// surface specific error codes.
#[test]
fn invalid_request_wrong_number_of_requested() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let creds = client.handle_response(&zero_resp, zero_validation).unwrap();

    let (valid_req, _) = client.create_request(&[0u64, 0u64], creds, &mut rng).unwrap();

    // Drop one requested credential.
    let mut requested: Vec<IssuanceRequest> = valid_req.requested().to_vec();
    requested.truncate(1);
    let tampered = RealCredentialsRequest::new(
        valid_req.delta(),
        valid_req.presented().to_vec(),
        requested,
        valid_req.proofs().to_vec(),
    );

    let err = issuer.handle_request(&tampered, &mut rng).unwrap_err();
    assert!(matches!(
        err,
        WabiSabiError::InvalidNumberOfRequestedCredentials { expected: 2, actual: 1 }
    ));
}

#[test]
fn invalid_request_wrong_number_of_presented() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let creds = client.handle_response(&zero_resp, zero_validation).unwrap();

    let (valid_req, _) = client.create_request(&[1u64, 0u64], creds, &mut rng).unwrap();

    // Drop one presented credential.
    let mut presented = valid_req.presented().to_vec();
    presented.truncate(1);
    let tampered = RealCredentialsRequest::new(
        valid_req.delta(),
        presented,
        valid_req.requested().to_vec(),
        valid_req.proofs().to_vec(),
    );

    let err = issuer.handle_request(&tampered, &mut rng).unwrap_err();
    assert!(matches!(
        err,
        WabiSabiError::InvalidNumberOfPresentedCredentials { expected: 2, actual: 1 }
    ));
}

#[test]
fn invalid_request_bad_bit_commitments() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let creds = client.handle_response(&zero_resp, zero_validation).unwrap();

    let (valid_req, _) = client.create_request(&[1u64, 0u64], creds, &mut rng).unwrap();

    // Replace second IssuanceRequest's bit commitments with a single infinity.
    let mut requested = valid_req.requested().to_vec();
    let bad = IssuanceRequest::new(requested[1].ma().clone(), vec![GroupElement::infinity()]);
    requested[1] = bad;
    let tampered = RealCredentialsRequest::new(
        valid_req.delta(),
        valid_req.presented().to_vec(),
        requested,
        valid_req.proofs().to_vec(),
    );

    let err = issuer.handle_request(&tampered, &mut rng).unwrap_err();
    assert!(matches!(err, WabiSabiError::InvalidBitCommitment));
}

#[test]
fn invalid_request_swapped_zero_proofs() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (valid_req, _) = client.create_request_for_zero_amount(&mut rng).unwrap();

    // Swap proofs so they no longer correspond to their requests.
    let mut proofs = valid_req.proofs().to_vec();
    proofs.swap(0, 1);
    let tampered = nwabisabi::credential_requesting::ZeroCredentialsRequest::new(
        valid_req.requested().to_vec(),
        proofs,
    );

    let err = issuer.handle_request(&tampered, &mut rng).unwrap_err();
    assert!(matches!(err, WabiSabiError::CoordinatorReceivedInvalidProofs));
}

#[test]
fn double_spend_serial_number_rejected() {
    let (client, issuer, mut rng) = fresh_pair(0);

    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let creds = client.handle_response(&zero_resp, zero_validation).unwrap();

    // First reissuance: succeeds.
    let (req1, validation1) = client.create_request(&[0u64, 0u64], creds.clone(), &mut rng).unwrap();
    let resp1 = issuer.handle_request(&req1, &mut rng).unwrap();
    let _new_creds = client.handle_response(&resp1, validation1).unwrap();

    // Second reissuance with the same serial numbers: must be rejected.
    let (req2, _validation2) = client.create_request(&[0u64, 0u64], creds, &mut rng).unwrap();
    let err = issuer.handle_request(&req2, &mut rng).unwrap_err();
    assert!(matches!(err, WabiSabiError::SerialNumberAlreadyUsed));
}

/// Port of `CredentialTests.CorrectRangeProof`: the range-proof width must
/// scale with the issuer's max amount, identically on client and issuer.
#[test]
fn range_proof_width_matches_max_amount() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let params = sk.compute_parameters().unwrap();

    // 4_300_000_000_000 fits in 42 bits.
    let issuer = CredentialIssuer::new(sk.clone(), 0)
        .unwrap()
        .with_max_amount(4_300_000_000_000);
    let client = WabiSabiClient::new(params.clone()).with_max_amount(4_300_000_000_000);
    assert_eq!(issuer.range_proof_width(), 42);
    assert_eq!(client.range_proof_width(), 42);

    // 4_400_000_000_001 needs 43 bits.
    let issuer = CredentialIssuer::new(sk, 0)
        .unwrap()
        .with_max_amount(4_400_000_000_001);
    let client = WabiSabiClient::new(params).with_max_amount(4_400_000_000_001);
    assert_eq!(issuer.range_proof_width(), 43);
    assert_eq!(client.range_proof_width(), 43);
}
