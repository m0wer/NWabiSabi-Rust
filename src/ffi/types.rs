use crate::crypto::{GroupElement, Scalar};
use crate::error::WabiSabiError;
use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

/// FFI-safe error codes
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FFIError {
    Success = 0,
    InvalidGroupElement = 1,
    InvalidScalar = 2,
    InvalidProof = 3,
    InvalidNumberOfCredentials = 4,
    InvalidNumberOfProofs = 5,
    SerialNumberAlreadyUsed = 6,
    CoordinatorReceivedInvalidProofs = 7,
    NegativeBalance = 8,
    InvalidMacProofs = 9,
    InvalidParameter = 10,
    NullPointer = 11,
    AllocationFailed = 12,
    Unknown = 999,
}

impl From<WabiSabiError> for FFIError {
    fn from(error: WabiSabiError) -> Self {
        match error {
            WabiSabiError::InvalidGroupElement => FFIError::InvalidGroupElement,
            WabiSabiError::InvalidScalar => FFIError::InvalidScalar,
            WabiSabiError::InvalidProof => FFIError::InvalidProof,
            WabiSabiError::InvalidNumberOfCredentials => FFIError::InvalidNumberOfCredentials,
            WabiSabiError::InvalidNumberOfProofs => FFIError::InvalidNumberOfProofs,
            WabiSabiError::SerialNumberAlreadyUsed => FFIError::SerialNumberAlreadyUsed,
            WabiSabiError::CoordinatorReceivedInvalidProofs => {
                FFIError::CoordinatorReceivedInvalidProofs
            }
            WabiSabiError::NegativeBalance(_) => FFIError::NegativeBalance,
            WabiSabiError::InvalidMacProofs => FFIError::InvalidMacProofs,
            WabiSabiError::InvalidParameter => FFIError::InvalidParameter,
            _ => FFIError::Unknown,
        }
    }
}

/// FFI-safe representation of a group element (33 bytes compressed)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FFIGroupElement {
    pub compressed: [u8; 33],
}

impl FFIGroupElement {
    /// Convert from Rust GroupElement to FFI
    pub fn from_group_element(element: &GroupElement) -> Self {
        Self {
            compressed: element.to_bytes(),
        }
    }

    /// Convert from FFI to Rust GroupElement
    pub fn to_group_element(&self) -> Result<GroupElement, WabiSabiError> {
        GroupElement::from_bytes(&self.compressed)
    }
}

/// FFI-safe representation of a scalar (32 bytes)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FFIScalar {
    pub bytes: [u8; 32],
}

impl FFIScalar {
    /// Convert from Rust Scalar to FFI
    pub fn from_scalar(scalar: &Scalar) -> Self {
        Self {
            bytes: scalar.to_bytes(),
        }
    }

    /// Convert from FFI to Rust Scalar
    pub fn to_scalar(&self) -> Result<Scalar, WabiSabiError> {
        Scalar::from_bytes(&self.bytes)
    }
}

/// FFI-safe array of group elements
#[repr(C)]
pub struct FFIGroupElementArray {
    pub elements: *mut FFIGroupElement,
    pub length: usize,
}

impl FFIGroupElementArray {
    /// Create from a vector of group elements
    pub fn from_vec(elements: Vec<GroupElement>) -> Self {
        let ffi_elements: Vec<FFIGroupElement> = elements
            .iter()
            .map(FFIGroupElement::from_group_element)
            .collect();

        let length = ffi_elements.len();
        let boxed = ffi_elements.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut FFIGroupElement;

        Self {
            elements: ptr,
            length,
        }
    }

    /// Convert to vector of group elements
    pub unsafe fn to_vec(&self) -> Result<Vec<GroupElement>, WabiSabiError> {
        if self.elements.is_null() {
            return Err(WabiSabiError::InvalidParameter);
        }

        let slice = slice::from_raw_parts(self.elements, self.length);
        slice.iter().map(|e| e.to_group_element()).collect()
    }

    /// Free the allocated memory
    pub unsafe fn free(self) {
        if !self.elements.is_null() {
            let _ = Box::from_raw(slice::from_raw_parts_mut(self.elements, self.length));
        }
    }
}

/// FFI-safe array of scalars
#[repr(C)]
pub struct FFIScalarArray {
    pub scalars: *mut FFIScalar,
    pub length: usize,
}

impl FFIScalarArray {
    /// Create from a vector of scalars
    pub fn from_vec(scalars: Vec<Scalar>) -> Self {
        let ffi_scalars: Vec<FFIScalar> = scalars.iter().map(FFIScalar::from_scalar).collect();

        let length = ffi_scalars.len();
        let boxed = ffi_scalars.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut FFIScalar;

        Self {
            scalars: ptr,
            length,
        }
    }

    /// Convert to vector of scalars
    pub unsafe fn to_vec(&self) -> Result<Vec<Scalar>, WabiSabiError> {
        if self.scalars.is_null() {
            return Err(WabiSabiError::InvalidParameter);
        }

        let slice = slice::from_raw_parts(self.scalars, self.length);
        slice.iter().map(|s| s.to_scalar()).collect()
    }

    /// Free the allocated memory
    pub unsafe fn free(self) {
        if !self.scalars.is_null() {
            let _ = Box::from_raw(slice::from_raw_parts_mut(self.scalars, self.length));
        }
    }
}

/// FFI-safe array of u64 amounts
#[repr(C)]
pub struct FFIAmountArray {
    pub amounts: *const u64,
    pub length: usize,
}

impl FFIAmountArray {
    /// Convert to vector
    pub unsafe fn to_vec(&self) -> Result<Vec<u64>, WabiSabiError> {
        if self.amounts.is_null() {
            return Err(WabiSabiError::InvalidParameter);
        }

        let slice = slice::from_raw_parts(self.amounts, self.length);
        Ok(slice.to_vec())
    }
}

/// Helper function to create C string from Rust string
pub fn rust_string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Helper function to free C string
pub unsafe fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

// Note: ffi_try and ffi_try_int macros are defined in src/ffi/mod.rs
