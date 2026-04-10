// Allow incomplete implementations during development
#![allow(dead_code)]
#![allow(unused_variables)]

pub mod constants;
pub mod credential_issuer;
pub mod credential_requesting;
pub mod crypto;
pub mod error;
pub mod ffi;
pub mod wabisabi_client;
pub mod zero_knowledge;

// Re-export commonly used types
pub use credential_issuer::CredentialIssuer;
pub use error::{Result, WabiSabiError};
pub use wabisabi_client::WabiSabiClient;

// Re-export generators for convenience
pub use crypto::Generators;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_imports() {
        use crate::crypto::*;
        let s = Scalar::zero();
        assert!(s.is_zero());
    }
}
