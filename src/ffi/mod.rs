/// Foreign Function Interface (FFI) layer for C interoperability
///
/// This module provides a C-compatible API for the WabiSabi protocol implementation.
/// All types are FFI-safe (#[repr(C)]) and use opaque pointers for complex Rust types.
///
/// # Safety
/// All functions in this module are marked as `unsafe` because they:
/// - Accept raw pointers from C
/// - Perform manual memory management
/// - Assume pointers are valid and properly aligned
///
/// Callers must ensure:
/// - Pointers are non-null unless explicitly documented as optional
/// - Pointers are properly aligned for their type
/// - Memory is freed using the appropriate `_destroy` functions
/// - Objects are not used after being destroyed

/// Helper macro to convert Result to FFI error code
#[macro_export]
macro_rules! ffi_try {
    ($expr:expr, $error:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                *$error = crate::ffi::types::FFIError::from(e);
                return std::ptr::null_mut();
            }
        }
    };
}

pub mod exports;
pub mod types;

// Re-export main types for convenience
pub use exports::*;
pub use types::*;
