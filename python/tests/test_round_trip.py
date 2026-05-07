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


# ---------------------------------------------------------------------------
# CLSAG ring-signature bindings (JMP-0006 EXT-1A)
# ---------------------------------------------------------------------------
#
# These are PyO3-binding-level smoke tests: the cryptographic edge cases
# are covered by the Rust unit tests in `src/crypto/clsag.rs`. Here we
# only verify the FFI shape (bytes in / bytes out, error mapping,
# `(ok, key_image)` tuple contract) round-trips correctly.

import secrets

import coincurve


def _ring_member() -> tuple[bytes, bytes]:
    """Generate `(secret_key_32, x_only_pubkey_32)` for one ring slot.

    The CLSAG ring expects BIP340 x-only pubkeys (even-Y lift). We
    derive the compressed pubkey via coincurve and flip the secret if
    the y-coordinate is odd, so the returned `(sk, xonly)` always
    satisfies `sk * G = lift_x(xonly)`.
    """
    while True:
        sk = secrets.token_bytes(32)
        try:
            pk = coincurve.PrivateKey(sk).public_key.format(compressed=True)
        except ValueError:
            continue  # invalid scalar (extremely rare); try again
        if pk[0] == 0x02:
            return sk, pk[1:]
        # Odd-Y: negate the secret so the new pubkey has even-Y.
        # Group order n for secp256k1.
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        flipped = (n - int.from_bytes(sk, "big")) % n
        sk2 = flipped.to_bytes(32, "big")
        return sk2, pk[1:]


def test_clsag_sign_verify_round_trip() -> None:
    """A signature produced by `clsag_sign` verifies and reveals its key image."""
    members = [_ring_member() for _ in range(5)]
    ring = [xonly for _, xonly in members]
    signer_idx = 2
    sk = members[signer_idx][0]

    run_id = b"run-001"
    msg = b"jmng/tx_extension_v1/attest:demo"

    sig = nwabisabi.clsag_sign(sk, ring, signer_idx, run_id, msg)
    assert isinstance(sig, bytes)
    assert len(sig) == 33 + 32 + 32 * len(ring)

    ok, key_image = nwabisabi.clsag_verify(sig, ring, run_id, msg)
    assert ok is True
    assert isinstance(key_image, bytes)
    assert len(key_image) == 33

    # `clsag_key_image` agrees with the value embedded in the signature.
    direct = nwabisabi.clsag_key_image(sk, run_id)
    assert direct == key_image


def test_clsag_verify_rejects_tampered_message() -> None:
    """Flipping the message fails verification but still yields the key image."""
    members = [_ring_member() for _ in range(3)]
    ring = [xonly for _, xonly in members]
    sk = members[0][0]

    sig = nwabisabi.clsag_sign(sk, ring, 0, b"r", b"orig")
    ok, _ = nwabisabi.clsag_verify(sig, ring, b"r", b"tampered")
    assert ok is False


def test_clsag_key_image_rotates_per_run() -> None:
    """Different `run_id`s for the same secret produce different key images."""
    members = [_ring_member() for _ in range(3)]
    sk = members[0][0]
    img_a = nwabisabi.clsag_key_image(sk, b"run-A")
    img_b = nwabisabi.clsag_key_image(sk, b"run-B")
    assert img_a != img_b


def test_clsag_sign_rejects_mismatched_signer_index() -> None:
    """Pointing `signer_idx` at the wrong ring slot raises `RuntimeError`."""
    members = [_ring_member() for _ in range(3)]
    ring = [xonly for _, xonly in members]
    sk_for_slot_0 = members[0][0]
    try:
        nwabisabi.clsag_sign(sk_for_slot_0, ring, 1, b"r", b"m")
    except RuntimeError as exc:
        assert "Invalid parameter" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected mismatched-slot signing to raise")


def test_clsag_verify_rejects_truncated_signature() -> None:
    """A short blob raises `RuntimeError` (DeserializationError)."""
    members = [_ring_member() for _ in range(3)]
    ring = [xonly for _, xonly in members]
    try:
        nwabisabi.clsag_verify(b"\x00" * 10, ring, b"r", b"m")
    except RuntimeError as exc:
        assert "expected" in str(exc) or "Deserialization" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected truncated-sig verify to raise")
