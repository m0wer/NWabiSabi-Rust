//! Python bindings for the WabiSabi credential protocol.
//!
//! All wire DTOs (`CredentialIssuerParameters`, `ZeroCredentialsRequest`,
//! `RealCredentialsRequest`, `CredentialsResponse`, `Mac`, `Credential`,
//! `CredentialPresentation`, `CredentialIssuerSecretKey`) cross the FFI
//! boundary as bincode-encoded `bytes`. Stateful objects with non-Serde
//! interiors (`WabiSabiClient`, `CredentialIssuer`, `ValidationHandle`,
//! `CredentialHandle`) are exposed as opaque PyO3 classes that the
//! caller threads through the round-trip.
//!
//! Design choices:
//!
//! * **Bincode at the boundary**: avoids defining a parallel Python-side
//!   class hierarchy. Rust stays the single source of truth for the
//!   wire format, and the Python wrapper layer can move to a different
//!   codec (CBOR, MsgPack) without touching the binding signatures.
//!
//! * **Opaque handles for non-Serde state**: `CredentialsResponseValidation`
//!   wraps a `Transcript` whose interior is a Strobe state that has no
//!   stable serialization. Forcing it through bytes would require
//!   either snapshotting the Strobe state (fragile across upstream
//!   crate versions) or re-deriving the transcript on each call (costly
//!   and racy). Holding it as a `#[pyclass]` keeps the round-trip type
//!   safe and zero-copy on the hot path.
//!
//! * **`SecureRandom` per call**: every call instantiates a fresh
//!   `SecureRandom` rather than threading one from Python. This matches
//!   the WabiSabi reference behaviour (system entropy on every proof)
//!   and keeps the Python API thread-safe without exposing a `Send +
//!   Sync` guarantee that the Rust RNG does not currently make.

use crate::credential_issuer::CredentialIssuer as RsIssuer;
use crate::credential_requesting::credentials_request::{
    RealCredentialsRequest, ZeroCredentialsRequest,
};
use crate::credential_requesting::credentials_response::CredentialsResponse;
use crate::credential_requesting::validation::CredentialsResponseValidation;
use crate::crypto::issuer_key::{CredentialIssuerParameters, CredentialIssuerSecretKey};
use crate::crypto::randomness::SecureRandom;
use crate::wabisabi_client::WabiSabiClient as RsClient;
use crate::zero_knowledge::Credential as RsCredential;
use crate::zero_knowledge::RegistrationShow as RsRegistrationShow;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Convert a `WabiSabiError` into a Python-level `RuntimeError`. Using
/// `RuntimeError` (rather than a custom exception) keeps the binding
/// dependency-free on the Python side; the `Display` impl already
/// carries enough detail for caller-side `except` matching by message.
fn wabisabi_err(e: crate::error::WabiSabiError) -> PyErr {
    PyRuntimeError::new_err(format!("{e}"))
}

fn bincode_err(e: bincode::Error) -> PyErr {
    PyValueError::new_err(format!("bincode: {e}"))
}

fn encode<T: serde::Serialize>(value: &T) -> PyResult<Vec<u8>> {
    bincode::serialize(value).map_err(bincode_err)
}

fn decode<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> PyResult<T> {
    bincode::deserialize(bytes).map_err(bincode_err)
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// Coordinator-side credential issuer.
///
/// Wraps `nwabisabi::CredentialIssuer`. The handle owns the issuer
/// secret key and an internal balance; `handle_request` mutates that
/// balance atomically.
///
/// Held inside an `Option` so the `configure` builder can move the
/// issuer through `with_max_amount` / `with_range_proof_width`
/// (which take `self` by value) without requiring the inner type to
/// be `Default`.
#[pyclass(name = "CredentialIssuer", module = "nwabisabi")]
pub struct PyIssuer {
    inner: Option<RsIssuer>,
}

impl PyIssuer {
    fn issuer(&self) -> &RsIssuer {
        self.inner
            .as_ref()
            .expect("issuer slot temporarily empty during configure(); not exposed")
    }
}

#[pymethods]
impl PyIssuer {
    /// Build an issuer from a serialized secret key and an initial
    /// balance ceiling. Mirrors `CredentialIssuer::new`.
    #[new]
    fn new(secret_key_bytes: &[u8], initial_balance: i64) -> PyResult<Self> {
        let sk: CredentialIssuerSecretKey = decode(secret_key_bytes)?;
        let inner = RsIssuer::new(sk, initial_balance).map_err(wabisabi_err)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Override the per-credential maximum value and corresponding
    /// range-proof width. Issuer and client *must* agree on these
    /// numbers or the issuer rejects every real-amount request with
    /// "Invalid bit commitment". Exposed because the in-crate Rust
    /// defaults (Wasabi-tuned `MAX_AMOUNT = 2**27`) are smaller than
    /// downstream protocols (e.g. JMP-0005 uses `2**51`) need.
    fn configure(&mut self, max_amount: i64, range_proof_width: usize) {
        let issuer = self
            .inner
            .take()
            .expect("issuer slot temporarily empty; configure() called re-entrantly");
        self.inner = Some(
            issuer
                .with_max_amount(max_amount)
                .with_range_proof_width(range_proof_width),
        );
    }

    /// Return the public issuer parameters (`CredentialIssuerParameters`)
    /// as bincode bytes for the client to consume.
    fn parameters<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = encode(self.issuer().parameters())?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Current issuer balance.
    fn balance(&self) -> i64 {
        self.issuer().balance()
    }

    /// Reset the issuer balance. Used between rounds.
    fn reset(&self, new_balance: i64) {
        self.issuer().reset(new_balance);
    }

    /// Process either a zero-amount or real-amount credentials request.
    ///
    /// `is_real` selects the deserialization target. The returned bytes
    /// hold a serialized `CredentialsResponse`.
    fn handle_request<'py>(
        &self,
        py: Python<'py>,
        request_bytes: &[u8],
        is_real: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut rng = SecureRandom::new();
        let response = if is_real {
            let req: RealCredentialsRequest = decode(request_bytes)?;
            self.issuer().handle_request(&req, &mut rng).map_err(wabisabi_err)?
        } else {
            let req: ZeroCredentialsRequest = decode(request_bytes)?;
            self.issuer().handle_request(&req, &mut rng).map_err(wabisabi_err)?
        };
        Ok(PyBytes::new_bound(py, &encode(&response)?))
    }

    /// Verify a JMP-0005 ZK-4 registration show.
    ///
    /// Returns the 33-byte compressed serial point on success;
    /// raises `RuntimeError` if the show fails any of:
    ///   * MAC binding (Z' != z_public),
    ///   * Sigma proof under `transcript_label`,
    ///   * revealed `amount` matching the rerandomized commitment.
    ///
    /// The caller is responsible for tracking serial uniqueness; this
    /// method does not consult the issuer's seen-serial set.
    fn verify_registration<'py>(
        &self,
        py: Python<'py>,
        show_bytes: &[u8],
        amount: i64,
        transcript_label: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let show: RsRegistrationShow = decode(show_bytes)?;
        let serial = self
            .issuer()
            .verify_registration_show(&show, amount, transcript_label)
            .map_err(wabisabi_err)?;
        Ok(PyBytes::new_bound(py, &serial))
    }
}

// ---------------------------------------------------------------------------
// Validation handle (round-trip state, no Serde)
// ---------------------------------------------------------------------------

/// Opaque per-request validation state.
///
/// Cannot be serialized: holds a Strobe-backed `Transcript`. The Python
/// caller is expected to keep the handle alive between
/// `create_request_*` and `handle_response`.
#[pyclass(name = "ValidationHandle", module = "nwabisabi")]
pub struct PyValidation {
    inner: Option<CredentialsResponseValidation>,
}

// ---------------------------------------------------------------------------
// Credential handle
// ---------------------------------------------------------------------------

/// Issued credential held client-side between rounds.
///
/// Exposed as bincode-encodable so the wallet layer can persist the
/// credentials between process restarts.
#[pyclass(name = "Credential", module = "nwabisabi")]
#[derive(Clone)]
pub struct PyCredential {
    inner: RsCredential,
}

#[pymethods]
impl PyCredential {
    /// Reconstruct a credential from its bincode encoding.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self { inner: decode(bytes)? })
    }

    /// Bincode encoding suitable for persistence.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &encode(&self.inner)?))
    }

    /// The credential's plaintext value (sat, signed; <= max_amount).
    fn value(&self) -> i64 {
        self.inner.value()
    }

    /// 33-byte compressed serial point `S = r * Gs`.
    ///
    /// Deterministic in the credential's randomness; coordinators dedupe
    /// shows on this byte-string.
    fn serial<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let s = self.inner.serial().map_err(wabisabi_err)?;
        Ok(PyBytes::new_bound(py, &s))
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Maker/taker-side WabiSabi client.
#[pyclass(name = "WabiSabiClient", module = "nwabisabi")]
pub struct PyClient {
    inner: RsClient,
}

#[pymethods]
impl PyClient {
    /// Build a client from the coordinator's serialized
    /// `CredentialIssuerParameters`.
    #[new]
    fn new(parameters_bytes: &[u8]) -> PyResult<Self> {
        let params: CredentialIssuerParameters = decode(parameters_bytes)?;
        Ok(Self { inner: RsClient::new(params) })
    }

    /// Configure the per-credential maximum amount and corresponding
    /// range-proof width. Mirrors the builder methods on the Rust
    /// client; chained via reassignment because Python lacks the
    /// move-by-value pattern.
    fn configure(&mut self, max_amount: i64, range_proof_width: usize) {
        // Reuse the underlying parameters to rebuild the client with
        // the new configuration. Cheaper than exposing two mutators
        // because `with_*` consume `self`.
        let params = self.inner.coordinator_parameters().clone();
        self.inner = RsClient::new(params)
            .with_max_amount(max_amount)
            .with_range_proof_width(range_proof_width);
    }

    /// Build a zero-amount credentials request (input registration).
    /// Returns `(request_bytes, validation_handle)`.
    fn create_request_for_zero_amount<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Py<PyValidation>)> {
        let mut rng = SecureRandom::new();
        let (request, validation) = self
            .inner
            .create_request_for_zero_amount(&mut rng)
            .map_err(wabisabi_err)?;
        let bytes = encode(&request)?;
        let handle = Py::new(py, PyValidation { inner: Some(validation) })?;
        Ok((PyBytes::new_bound(py, &bytes), handle))
    }

    /// Build a real-amount credentials request (output / reissuance).
    /// `amounts` length must equal the protocol `CREDENTIAL_NUMBER`.
    /// Returns `(request_bytes, validation_handle)`.
    fn create_request<'py>(
        &self,
        py: Python<'py>,
        amounts: Vec<u64>,
        credentials_to_present: Vec<PyCredential>,
    ) -> PyResult<(Bound<'py, PyBytes>, Py<PyValidation>)> {
        let mut rng = SecureRandom::new();
        let presented: Vec<RsCredential> =
            credentials_to_present.into_iter().map(|c| c.inner).collect();
        let (request, validation) = self
            .inner
            .create_request(&amounts, presented, &mut rng)
            .map_err(wabisabi_err)?;
        let bytes = encode(&request)?;
        let handle = Py::new(py, PyValidation { inner: Some(validation) })?;
        Ok((PyBytes::new_bound(py, &bytes), handle))
    }

    /// Validate a coordinator response and return the issued credentials.
    /// Consumes the validation handle (subsequent calls raise).
    fn handle_response(
        &self,
        response_bytes: &[u8],
        validation: &Bound<'_, PyValidation>,
    ) -> PyResult<Vec<PyCredential>> {
        let response: CredentialsResponse = decode(response_bytes)?;
        let v = validation
            .borrow_mut()
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("validation handle already consumed"))?;
        let credentials = self.inner.handle_response(&response, v).map_err(wabisabi_err)?;
        Ok(credentials.into_iter().map(|c| PyCredential { inner: c }).collect())
    }

    /// Build a JMP-0005 ZK-4 registration-show blob for `credential`.
    ///
    /// `transcript_label` should encode every output-bound field the
    /// caller wants to make non-malleable (epoch id, address, amount,
    /// output type). Returns bincode-encoded `RegistrationShow` bytes.
    fn present_for_registration<'py>(
        &self,
        py: Python<'py>,
        credential: PyCredential,
        transcript_label: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut rng = SecureRandom::new();
        let show = RsRegistrationShow::prove(
            &credential.inner,
            self.inner.coordinator_parameters(),
            transcript_label,
            &mut rng,
        )
        .map_err(wabisabi_err)?;
        Ok(PyBytes::new_bound(py, &encode(&show)?))
    }
}

// ---------------------------------------------------------------------------
// Top-level helpers
// ---------------------------------------------------------------------------

/// Generate a fresh issuer secret key from system entropy.
/// Returns the bincode-encoded `CredentialIssuerSecretKey`.
#[pyfunction]
fn generate_issuer_secret_key(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    let mut rng = SecureRandom::new();
    let sk = CredentialIssuerSecretKey::new(&mut rng);
    Ok(PyBytes::new_bound(py, &encode(&sk)?))
}

/// Compute the public `CredentialIssuerParameters` for a given secret key.
#[pyfunction]
fn derive_issuer_parameters<'py>(
    py: Python<'py>,
    secret_key_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk: CredentialIssuerSecretKey = decode(secret_key_bytes)?;
    let params = sk.compute_parameters().map_err(wabisabi_err)?;
    Ok(PyBytes::new_bound(py, &encode(&params)?))
}

// ---------------------------------------------------------------------------
// CLSAG-style ring signatures (linkable, secp256k1)
// ---------------------------------------------------------------------------
//
// Wire shape stays byte-oriented to match the IRC-level transport that
// consumes these. Ring members travel as 32-byte x-only pubkeys
// (BIP340 form) so the caller can pass slices straight from a
// pubkey-list field. The signature itself is the canonical
// `33 + 32 + 32*N` blob produced by `RingSignature::to_bytes`.

use crate::crypto::clsag::{self, RingSignature};
use crate::crypto::generators::Generators;
use crate::crypto::Scalar;

/// Coerce a Python `list[bytes]` of x-only ring members into the
/// `[[u8; 32]]` form `clsag::sign`/`verify` expect.
fn ring_from_py(ring: &[Vec<u8>]) -> PyResult<Vec<[u8; 32]>> {
    ring.iter()
        .enumerate()
        .map(|(i, p)| {
            <[u8; 32]>::try_from(p.as_slice()).map_err(|_| {
                PyValueError::new_err(format!(
                    "ring[{i}]: expected 32-byte x-only pubkey, got {} bytes",
                    p.len()
                ))
            })
        })
        .collect()
}

fn scalar_from_secret(bytes: &[u8]) -> PyResult<Scalar> {
    let arr = <[u8; 32]>::try_from(bytes)
        .map_err(|_| PyValueError::new_err("secret_key: expected 32 bytes"))?;
    Ok(Scalar::from_bytes_reduced(&arr))
}

/// Sign `message` over `ring_xonly` at `signer_idx` with `secret_key`.
///
/// `secret_key` is a 32-byte big-endian scalar. `ring_xonly` is a list
/// of 32-byte BIP340 x-only pubkeys; `ring_xonly[signer_idx]` MUST
/// match `secret_key * G` lifted to even-Y, otherwise this raises
/// `RuntimeError`. Returns the signature blob (`33 + 32 + 32*N` bytes).
#[pyfunction]
fn clsag_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    ring_xonly: Vec<Vec<u8>>,
    signer_idx: usize,
    run_id: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let ring = ring_from_py(&ring_xonly)?;
    let sk = scalar_from_secret(secret_key)?;
    let mut rng = SecureRandom::new();
    let sig = clsag::sign(&ring, signer_idx, &sk, run_id, message, &mut rng)
        .map_err(wabisabi_err)?;
    Ok(PyBytes::new_bound(py, &sig.to_bytes()))
}

/// Verify a CLSAG ring signature.
///
/// Returns `(ok, key_image_bytes)`. `key_image_bytes` is the 33-byte
/// compressed wire-form key image extracted from `signature_bytes`,
/// regardless of validity, so the caller can dedupe at the gossip
/// layer without re-parsing the blob. `ok` is `True` iff the signature
/// is valid for `(ring_xonly, run_id, message)`.
#[pyfunction]
fn clsag_verify<'py>(
    py: Python<'py>,
    signature_bytes: &[u8],
    ring_xonly: Vec<Vec<u8>>,
    run_id: &[u8],
    message: &[u8],
) -> PyResult<(bool, Bound<'py, PyBytes>)> {
    let ring = ring_from_py(&ring_xonly)?;
    let sig = RingSignature::from_bytes(signature_bytes, ring.len()).map_err(wabisabi_err)?;
    let key_image = sig.key_image.to_bytes();
    let ok = clsag::verify(&ring, &sig, run_id, message).is_ok();
    Ok((ok, PyBytes::new_bound(py, &key_image)))
}

/// Compute the per-run key image for `secret_key` without producing a
/// full signature. Useful for callers that need a pre-flight Sybil
/// check (reject duplicate identity commitments before requesting the
/// full attestation).
#[pyfunction]
fn clsag_key_image<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    run_id: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = scalar_from_secret(secret_key)?;
    // I = H_p(P) * x + H_s("rotate" || run_id) * G. We replicate the
    // call sequence rather than exposing the helpers, keeping the
    // module-level DSTs encapsulated.
    let g = *Generators::g();
    let p = g.multiply(&sk).map_err(wabisabi_err)?;
    let h_p = clsag::hash_to_point_for_python(&p.to_bytes()).map_err(wabisabi_err)?;
    let i_core = h_p.multiply(&sk).map_err(wabisabi_err)?;
    let rot = clsag::run_rotation_scalar_for_python(run_id);
    let rot_g = g.multiply(&rot).map_err(wabisabi_err)?;
    let key_image = (i_core + rot_g).map_err(wabisabi_err)?;
    Ok(PyBytes::new_bound(py, &key_image.to_bytes()))
}

#[pymodule]
fn nwabisabi(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIssuer>()?;
    m.add_class::<PyClient>()?;
    m.add_class::<PyValidation>()?;
    m.add_class::<PyCredential>()?;
    m.add_function(wrap_pyfunction!(generate_issuer_secret_key, m)?)?;
    m.add_function(wrap_pyfunction!(derive_issuer_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_sign, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_verify, m)?)?;
    m.add_function(wrap_pyfunction!(clsag_key_image, m)?)?;
    Ok(())
}
