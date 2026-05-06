//! End-to-end round trip: zero issuance -> reissuance with real amounts.

use nwabisabi::credential_requesting::CredentialsRequest;
use nwabisabi::crypto::randomness::SecureRandom;
use nwabisabi::crypto::CredentialIssuerSecretKey;
use nwabisabi::{CredentialIssuer, WabiSabiClient};

#[test]
fn zero_then_real_round_trip() {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    let params = sk.compute_parameters().unwrap();
    let issuer = CredentialIssuer::new(sk, 0).unwrap();
    let client = WabiSabiClient::new(params);

    // Step 1: bootstrap two zero-value credentials.
    let (zero_req, zero_validation) = client.create_request_for_zero_amount(&mut rng).unwrap();
    let zero_resp = issuer.handle_request(&zero_req, &mut rng).unwrap();
    let zero_creds = client.handle_response(&zero_resp, zero_validation).unwrap();
    assert_eq!(zero_creds.len(), 2);
    for c in &zero_creds {
        assert_eq!(c.value(), 0);
    }

    // Step 2: spend the two zero credentials and request 100 + 250 sat.
    let amounts = [100u64, 250u64];
    let (real_req, real_validation) =
        client.create_request(&amounts, zero_creds, &mut rng).unwrap();
    assert_eq!(real_req.delta(), 350);
    assert_eq!(real_req.presented().len(), 2);
    assert_eq!(real_req.requested().len(), 2);

    let real_resp = issuer.handle_request(&real_req, &mut rng).unwrap();
    let real_creds = client.handle_response(&real_resp, real_validation).unwrap();
    assert_eq!(real_creds.len(), 2);
    let mut values: Vec<i64> = real_creds.iter().map(|c| c.value()).collect();
    values.sort();
    assert_eq!(values, vec![100, 250]);

    // Coordinator balance increased by delta.
    assert_eq!(issuer.balance(), 350);
}
