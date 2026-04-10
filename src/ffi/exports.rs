use super::types::*;
use crate::credential_issuer::CredentialIssuer;
use crate::crypto::randomness::SecureRandom;
use crate::crypto::CredentialIssuerSecretKey;
use crate::wabisabi_client::WabiSabiClient;
use std::os::raw::c_longlong;

/// Opaque pointer to WabiSabiClient
#[repr(C)]
pub struct OpaqueClient {
    _private: [u8; 0],
}

/// Opaque pointer to CredentialIssuer
#[repr(C)]
pub struct OpaqueIssuer {
    _private: [u8; 0],
}

/// Opaque pointer to SecureRandom
#[repr(C)]
pub struct OpaqueRandom {
    _private: [u8; 0],
}

/// Opaque pointer to Credential
#[repr(C)]
pub struct OpaqueCredential {
    _private: [u8; 0],
}

/// Create a new secure random number generator
///
/// # Safety
/// Caller must call wabisabi_random_destroy when done
#[no_mangle]
pub unsafe extern "C" fn wabisabi_random_create(error: *mut FFIError) -> *mut OpaqueRandom {
    let random = Box::new(SecureRandom::new());
    Box::into_raw(random) as *mut OpaqueRandom
}

/// Destroy a random number generator
///
/// # Safety
/// Pointer must have been created by wabisabi_random_create
#[no_mangle]
pub unsafe extern "C" fn wabisabi_random_destroy(random: *mut OpaqueRandom) {
    if !random.is_null() {
        let _ = Box::from_raw(random as *mut SecureRandom);
    }
}

/// Create a new WabiSabi client
///
/// # Arguments
/// * `coordinator_params_cw` - Coordinator's public parameter Cw
/// * `coordinator_params_i` - Coordinator's public parameter I
/// * `error` - Output parameter for error code
///
/// # Returns
/// Opaque pointer to client, or null on error
///
/// # Safety
/// Caller must call wabisabi_client_destroy when done
#[no_mangle]
pub unsafe extern "C" fn wabisabi_client_create(
    coordinator_params_cw: *const FFIGroupElement,
    coordinator_params_i: *const FFIGroupElement,
    error: *mut FFIError,
) -> *mut OpaqueClient {
    if coordinator_params_cw.is_null() || coordinator_params_i.is_null() {
        if !error.is_null() {
            *error = FFIError::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let cw = ffi_try!((*coordinator_params_cw).to_group_element(), error);
    let i = ffi_try!((*coordinator_params_i).to_group_element(), error);

    let params = crate::crypto::CredentialIssuerParameters { cw, i };
    let client = Box::new(WabiSabiClient::new(params));

    if !error.is_null() {
        *error = FFIError::Success;
    }

    Box::into_raw(client) as *mut OpaqueClient
}

/// Destroy a WabiSabi client
///
/// # Safety
/// Pointer must have been created by wabisabi_client_create
#[no_mangle]
pub unsafe extern "C" fn wabisabi_client_destroy(client: *mut OpaqueClient) {
    if !client.is_null() {
        let _ = Box::from_raw(client as *mut WabiSabiClient);
    }
}

/// Create a request for zero-value credentials
///
/// # Arguments
/// * `client` - The client
/// * `random` - Random number generator
/// * `randomness_out` - Output array for secret randomness (caller must free)
/// * `error` - Output parameter for error code
///
/// # Returns
/// Opaque pointer to ZeroCredentialsRequest, or null on error
///
/// # Safety
/// All pointers must be valid. Caller must free returned request and randomness_out
#[no_mangle]
pub unsafe extern "C" fn wabisabi_client_create_zero_request(
    client: *const OpaqueClient,
    random: *mut OpaqueRandom,
    randomness_out: *mut FFIScalarArray,
    error: *mut FFIError,
) -> *mut u8 {
    if client.is_null() || random.is_null() {
        if !error.is_null() {
            *error = FFIError::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let client = &*(client as *const WabiSabiClient);
    let random = &mut *(random as *mut SecureRandom);

    let (request, randomness) = ffi_try!(client.create_request_for_zero_amount(random), error);

    // Store randomness in output parameter
    if !randomness_out.is_null() {
        *randomness_out = FFIScalarArray::from_vec(randomness);
    }

    let boxed = Box::new(request);
    if !error.is_null() {
        *error = FFIError::Success;
    }

    Box::into_raw(boxed) as *mut u8
}

/// Create a new credential issuer
///
/// # Arguments
/// * `secret_key_w`, `secret_key_wp`, `secret_key_x0`, `secret_key_x1`, `secret_key_ya` - Secret key components
/// * `initial_balance` - Starting balance
/// * `cw_out` - Output for public parameter Cw
/// * `i_out` - Output for public parameter I
/// * `error` - Output parameter for error code
///
/// # Returns
/// Opaque pointer to issuer, or null on error
///
/// # Safety
/// Caller must call wabisabi_issuer_destroy when done
#[no_mangle]
pub unsafe extern "C" fn wabisabi_issuer_create(
    secret_key_w: *const FFIScalar,
    secret_key_wp: *const FFIScalar,
    secret_key_x0: *const FFIScalar,
    secret_key_x1: *const FFIScalar,
    secret_key_ya: *const FFIScalar,
    initial_balance: c_longlong,
    cw_out: *mut FFIGroupElement,
    i_out: *mut FFIGroupElement,
    error: *mut FFIError,
) -> *mut OpaqueIssuer {
    if secret_key_w.is_null()
        || secret_key_wp.is_null()
        || secret_key_x0.is_null()
        || secret_key_x1.is_null()
        || secret_key_ya.is_null()
    {
        if !error.is_null() {
            *error = FFIError::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let w = ffi_try!((*secret_key_w).to_scalar(), error);
    let wp = ffi_try!((*secret_key_wp).to_scalar(), error);
    let x0 = ffi_try!((*secret_key_x0).to_scalar(), error);
    let x1 = ffi_try!((*secret_key_x1).to_scalar(), error);
    let ya = ffi_try!((*secret_key_ya).to_scalar(), error);

    let sk = CredentialIssuerSecretKey { w, wp, x0, x1, ya };
    let params = ffi_try!(sk.compute_parameters(), error);

    // Output public parameters
    if !cw_out.is_null() {
        *cw_out = FFIGroupElement::from_group_element(&params.cw);
    }
    if !i_out.is_null() {
        *i_out = FFIGroupElement::from_group_element(&params.i);
    }

    let issuer = ffi_try!(CredentialIssuer::new(sk, initial_balance), error);
    let boxed = Box::new(issuer);

    if !error.is_null() {
        *error = FFIError::Success;
    }

    Box::into_raw(boxed) as *mut OpaqueIssuer
}

/// Create an issuer with randomly generated secret key
///
/// # Arguments
/// * `random` - Random number generator
/// * `initial_balance` - Starting balance
/// * `cw_out` - Output for public parameter Cw
/// * `i_out` - Output for public parameter I
/// * `error` - Output parameter for error code
///
/// # Returns
/// Opaque pointer to issuer, or null on error
///
/// # Safety
/// Caller must call wabisabi_issuer_destroy when done
#[no_mangle]
pub unsafe extern "C" fn wabisabi_issuer_create_random(
    random: *mut OpaqueRandom,
    initial_balance: c_longlong,
    cw_out: *mut FFIGroupElement,
    i_out: *mut FFIGroupElement,
    error: *mut FFIError,
) -> *mut OpaqueIssuer {
    if random.is_null() {
        if !error.is_null() {
            *error = FFIError::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let random = &mut *(random as *mut SecureRandom);
    let sk = CredentialIssuerSecretKey::new(random);
    let params = ffi_try!(sk.compute_parameters(), error);

    // Output public parameters
    if !cw_out.is_null() {
        *cw_out = FFIGroupElement::from_group_element(&params.cw);
    }
    if !i_out.is_null() {
        *i_out = FFIGroupElement::from_group_element(&params.i);
    }

    let issuer = ffi_try!(CredentialIssuer::new(sk, initial_balance), error);
    let boxed = Box::new(issuer);

    if !error.is_null() {
        *error = FFIError::Success;
    }

    Box::into_raw(boxed) as *mut OpaqueIssuer
}

/// Destroy a credential issuer
///
/// # Safety
/// Pointer must have been created by wabisabi_issuer_create
#[no_mangle]
pub unsafe extern "C" fn wabisabi_issuer_destroy(issuer: *mut OpaqueIssuer) {
    if !issuer.is_null() {
        let _ = Box::from_raw(issuer as *mut CredentialIssuer);
    }
}

/// Get the current balance of an issuer
///
/// # Safety
/// Issuer pointer must be valid
#[no_mangle]
pub unsafe extern "C" fn wabisabi_issuer_get_balance(issuer: *const OpaqueIssuer) -> c_longlong {
    if issuer.is_null() {
        return -1;
    }

    let issuer = &*(issuer as *const CredentialIssuer);
    issuer.balance()
}

/// Free an FFI scalar array
///
/// # Safety
/// Array must have been created by an FFI function
#[no_mangle]
pub unsafe extern "C" fn wabisabi_free_scalar_array(array: FFIScalarArray) {
    array.free();
}

/// Free an FFI group element array
///
/// # Safety
/// Array must have been created by an FFI function
#[no_mangle]
pub unsafe extern "C" fn wabisabi_free_group_element_array(array: FFIGroupElementArray) {
    array.free();
}

/// Get version string
///
/// # Returns
/// Pointer to version string (static, no need to free)
#[no_mangle]
pub extern "C" fn wabisabi_version() -> *const std::os::raw::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::os::raw::c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_create_random() {
        unsafe {
            let mut error = FFIError::Success;
            let random = wabisabi_random_create(&mut error);
            assert!(!random.is_null());
            assert_eq!(error, FFIError::Success);

            wabisabi_random_destroy(random);
        }
    }

    #[test]
    fn test_ffi_create_issuer() {
        unsafe {
            let mut error = FFIError::Success;
            let random = wabisabi_random_create(&mut error);
            assert!(!random.is_null());

            let mut cw = FFIGroupElement {
                compressed: [0; 33],
            };
            let mut i = FFIGroupElement {
                compressed: [0; 33],
            };

            let issuer =
                wabisabi_issuer_create_random(random, 1000000, &mut cw, &mut i, &mut error);
            assert!(!issuer.is_null());
            assert_eq!(error, FFIError::Success);

            let balance = wabisabi_issuer_get_balance(issuer);
            assert_eq!(balance, 1000000);

            wabisabi_issuer_destroy(issuer);
            wabisabi_random_destroy(random);
        }
    }
}
