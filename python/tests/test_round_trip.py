"""End-to-end round-trip tests for the nwabisabi PyO3 bindings.

Exercises the same flows covered by the Rust integration tests
(``tests/round_trip_tests.rs``) at the Python boundary, to catch
serialization, lifetime, and exception-mapping regressions in the
binding layer itself.
"""
from __future__ import annotations

import nwabisabi


CREDENTIAL_NUMBER = 2  # matches `nwabisabi::constants::CREDENTIAL_NUMBER`
MAX_AMOUNT = 1 << 27   # 2^27 sat default ceiling (RANGE_PROOF_WIDTH=27)


def _setup() -> tuple[nwabisabi.CredentialIssuer, nwabisabi.WabiSabiClient]:
    sk = nwabisabi.generate_issuer_secret_key()
    issuer = nwabisabi.CredentialIssuer(sk, MAX_AMOUNT)
    client = nwabisabi.WabiSabiClient(issuer.parameters())
    return issuer, client


def test_zero_amount_round_trip() -> None:
    """Mint zero-value credentials and verify their issuance proofs."""
    issuer, client = _setup()

    request_bytes, validation = client.create_request_for_zero_amount()
    assert isinstance(request_bytes, bytes)
    assert isinstance(validation, nwabisabi.ValidationHandle)

    response_bytes = issuer.handle_request(request_bytes, is_real=False)
    credentials = client.handle_response(response_bytes, validation)

    assert len(credentials) == CREDENTIAL_NUMBER
    for cred in credentials:
        assert cred.value() == 0


def test_real_amount_round_trip() -> None:
    """Mint zero credentials, then reissue against a real-value request."""
    issuer, client = _setup()

    # Step 1: mint zero credentials so we have something to present.
    req0, val0 = client.create_request_for_zero_amount()
    resp0 = issuer.handle_request(req0, is_real=False)
    zero_creds = client.handle_response(resp0, val0)

    # Step 2: present them and reissue against a real-value vector.
    amounts = [10_000, 5_000]
    assert len(amounts) == CREDENTIAL_NUMBER
    issuer.reset(sum(amounts))  # let the issuer fund this round's delta

    req1, val1 = client.create_request(amounts, zero_creds)
    resp1 = issuer.handle_request(req1, is_real=True)
    new_creds = client.handle_response(resp1, val1)

    assert sorted(c.value() for c in new_creds) == sorted(amounts)


def test_validation_handle_consumed_once() -> None:
    """A validation handle cannot be reused across two response calls."""
    issuer, client = _setup()

    req, val = client.create_request_for_zero_amount()
    resp = issuer.handle_request(req, is_real=False)
    client.handle_response(resp, val)

    try:
        client.handle_response(resp, val)
    except RuntimeError as exc:
        assert "validation handle already consumed" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected double-consume to raise")


def test_credential_persistence_round_trip() -> None:
    """Credentials survive serialize/deserialize via the bytes codec."""
    issuer, client = _setup()
    req, val = client.create_request_for_zero_amount()
    resp = issuer.handle_request(req, is_real=False)
    creds = client.handle_response(resp, val)

    for original in creds:
        blob = original.to_bytes()
        restored = nwabisabi.Credential.from_bytes(blob)
        assert restored.value() == original.value()


def test_derive_issuer_parameters_matches_issuer() -> None:
    """Standalone parameter derivation agrees with `CredentialIssuer.parameters()`."""
    sk = nwabisabi.generate_issuer_secret_key()
    issuer = nwabisabi.CredentialIssuer(sk, MAX_AMOUNT)
    assert nwabisabi.derive_issuer_parameters(sk) == issuer.parameters()
