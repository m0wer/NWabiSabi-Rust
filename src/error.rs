use thiserror::Error;

/// Error type for WabiSabi cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum WabiSabiError {
    #[error("Unspecified error")]
    Unspecified,

    #[error("Serial number already used")]
    SerialNumberAlreadyUsed,

    #[error("Coordinator received invalid proofs")]
    CoordinatorReceivedInvalidProofs,

    #[error("Negative balance: {0}")]
    NegativeBalance(i64),

    #[error("Invalid bit commitment")]
    InvalidBitCommitment,

    #[error("Client received invalid proofs")]
    ClientReceivedInvalidProofs,

    #[error("Issued credential count mismatch: expected {expected}, got {actual}")]
    IssuedCredentialNumberMismatch { expected: usize, actual: usize },

    #[error("Serial number duplicated in request")]
    SerialNumberDuplicated,

    #[error("Not enough zero credentials to fill the request")]
    NotEnoughZeroCredentialToFillTheRequest,

    #[error("Invalid number of requested credentials: expected {expected}, got {actual}")]
    InvalidNumberOfRequestedCredentials { expected: usize, actual: usize },

    #[error("Invalid number of presented credentials: expected {expected}, got {actual}")]
    InvalidNumberOfPresentedCredentials { expected: usize, actual: usize },

    #[error("Credential to present duplicated")]
    CredentialToPresentDuplicated,

    #[error("Invalid scalar value")]
    InvalidScalar,

    #[error("Invalid group element")]
    InvalidGroupElement,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid number of credentials")]
    InvalidNumberOfCredentials,

    #[error("Invalid number of proofs")]
    InvalidNumberOfProofs,

    #[error("Invalid MAC proofs")]
    InvalidMacProofs,

    #[error("Invalid parameter")]
    InvalidParameter,

    #[error("Invalid amount")]
    InvalidAmount,

    #[error("Value cannot be zero. (Parameter '{name}')")]
    ZeroScalar { name: &'static str },

    #[error("Point at infinity is not a valid value. (Parameter '{name}')")]
    PointAtInfinity { name: &'static str },
}

/// Result type for WabiSabi operations
pub type Result<T> = std::result::Result<T, WabiSabiError>;
