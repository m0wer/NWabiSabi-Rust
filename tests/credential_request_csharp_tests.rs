//! Direct port of WalletWasabi credential-request equality tests.
//!
//! Source files:
//!   - WalletWasabi.Tests/UnitTests/WabiSabi/Crypto/CredentialRequesting/
//!         ZeroCredentialsRequestTests.cs
//!   - WalletWasabi.Tests/UnitTests/WabiSabi/Crypto/CredentialRequesting/
//!         RealCredentialsRequestTests.cs
//!
//! Both upstream tests verify structural equality of the request DTOs that
//! flow over the wire between the WabiSabi client and the coordinator. The
//! `modifier` argument lets the helper produce two requests that differ only
//! in the `Ma` attribute commitment, so the equality check distinguishes
//! "same content, different instance" from "different content".

use nwabisabi::credential_requesting::{
    IssuanceRequest, RealCredentialsRequest, ZeroCredentialsRequest,
};
use nwabisabi::crypto::{Generators, GroupElement, GroupElementVector, Scalar, ScalarVector};
use nwabisabi::zero_knowledge::{CredentialPresentation, Proof};

fn new_group_element(i: u32) -> GroupElement {
    Generators::from_text(&format!("T{}", i))
}

fn new_group_element_vector(values: &[u32]) -> GroupElementVector {
    GroupElementVector::new(values.iter().copied().map(new_group_element).collect())
}

fn new_scalar_vector(values: &[u32]) -> ScalarVector {
    ScalarVector::new(
        values
            .iter()
            .copied()
            .map(|v| Scalar::from_u64(u64::from(v)))
            .collect(),
    )
}

fn make_zero_credentials_request(modifier: u32) -> ZeroCredentialsRequest {
    let requested = vec![IssuanceRequest::new(
        new_group_element(modifier * 1),
        vec![new_group_element(2), new_group_element(3)],
    )];
    let proofs = vec![Proof::new(
        new_group_element_vector(&[1, 2]),
        new_scalar_vector(&[6, 7]),
    )];
    ZeroCredentialsRequest::new(requested, proofs)
}

fn make_real_credentials_request(modifier: u32) -> RealCredentialsRequest {
    let presented = vec![CredentialPresentation::new(
        new_group_element(7),
        new_group_element(7),
        new_group_element(7),
        new_group_element(7),
        new_group_element(7),
    )
    .expect("CredentialPresentation::new is infallible for non-infinity inputs")];
    let requested = vec![IssuanceRequest::new(
        new_group_element(modifier * 1),
        vec![new_group_element(2), new_group_element(3)],
    )];
    let proofs = vec![Proof::new(
        new_group_element_vector(&[13]),
        new_scalar_vector(&[5]),
    )];
    RealCredentialsRequest::new(123_456, presented, requested, proofs)
}

/// Port of `ZeroCredentialsRequestTests.EqualityTest`.
#[test]
fn zero_credentials_request_equality() {
    let request1 = make_zero_credentials_request(1);
    let request2 = make_zero_credentials_request(1);

    // Two independently constructed requests with the same content must be equal.
    assert_eq!(request1, request2);

    let request3 = make_zero_credentials_request(2);
    // A different `Ma` modifier must yield a non-equal request.
    assert_ne!(request1, request3);
}

/// Port of `RealCredentialsRequestTests.EqualityTest`.
#[test]
fn real_credentials_request_equality() {
    let request1 = make_real_credentials_request(1);
    let request2 = make_real_credentials_request(1);

    assert_eq!(request1, request2);

    let request3 = make_real_credentials_request(2);
    assert_ne!(request1, request3);
}

/// Sanity: the `delta` and accessor surface match what the protocol expects
/// (zero-value request reports delta=0 and no presentations; real request
/// echoes the constructor's delta and exposes the presentations slice).
#[test]
fn request_accessors_round_trip() {
    use nwabisabi::credential_requesting::CredentialsRequest;

    let zero = make_zero_credentials_request(1);
    assert_eq!(zero.delta(), 0);
    assert!(zero.presented().is_empty());
    assert_eq!(zero.requested().len(), 1);
    assert_eq!(zero.proofs().len(), 1);

    let real = make_real_credentials_request(1);
    assert_eq!(real.delta(), 123_456);
    assert_eq!(real.presented().len(), 1);
    assert_eq!(real.requested().len(), 1);
    assert_eq!(real.proofs().len(), 1);
}
