# NWabiSabi FFI Guide

This guide explains how to use the NWabiSabi library from C and other languages via the Foreign Function Interface (FFI).

## Overview

The FFI layer provides a C-compatible API for the WabiSabi anonymous credential protocol. All complex Rust types are hidden behind opaque pointers, and all functions use C-compatible types.

## Building the Library

### Static Library

```bash
cargo build --release
```

This produces:
- `target/release/libnwabisabi.a` (static library)
- `target/release/libnwabisabi.so` (dynamic library on Linux)
- `target/release/libnwabisabi.dylib` (dynamic library on macOS)
- `target/release/nwabisabi.dll` (dynamic library on Windows)

### Generate C Headers

Install cbindgen:
```bash
cargo install cbindgen
```

Generate headers:
```bash
cbindgen --config cbindgen.toml --output include/nwabisabi.h
```

## Core Types

### Opaque Pointers

Complex Rust structures are exposed via opaque pointers:

```c
typedef struct OpaqueClient WabiSabiClient;
typedef struct OpaqueIssuer CredentialIssuer;
typedef struct OpaqueRandom Random;
typedef struct OpaqueCredential Credential;
```

These pointers must be created and destroyed using the provided functions.

### FFI-Safe Types

```c
// Error codes
typedef enum FFIError {
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
    Unknown = 999
} FFIError;

// Group element (compressed point, 33 bytes)
typedef struct FFIGroupElement {
    uint8_t compressed[33];
} FFIGroupElement;

// Scalar (32 bytes)
typedef struct FFIScalar {
    uint8_t bytes[32];
} FFIScalar;

// Array of group elements
typedef struct FFIGroupElementArray {
    FFIGroupElement* elements;
    size_t length;
} FFIGroupElementArray;

// Array of scalars
typedef struct FFIScalarArray {
    FFIScalar* scalars;
    size_t length;
} FFIScalarArray;
```

## API Functions

### Random Number Generation

```c
// Create a cryptographically secure RNG
Random* wabisabi_random_create(FFIError* error);

// Destroy RNG
void wabisabi_random_destroy(Random* random);
```

### Coordinator (Issuer) API

```c
// Create issuer with random secret key
CredentialIssuer* wabisabi_issuer_create_random(
    Random* random,
    long long initial_balance,
    FFIGroupElement* cw_out,      // Output: public parameter Cw
    FFIGroupElement* i_out,        // Output: public parameter I
    FFIError* error
);

// Create issuer with specific secret key
CredentialIssuer* wabisabi_issuer_create(
    const FFIScalar* secret_key_w,
    const FFIScalar* secret_key_wp,
    const FFIScalar* secret_key_x0,
    const FFIScalar* secret_key_x1,
    const FFIScalar* secret_key_ya,
    long long initial_balance,
    FFIGroupElement* cw_out,
    FFIGroupElement* i_out,
    FFIError* error
);

// Destroy issuer
void wabisabi_issuer_destroy(CredentialIssuer* issuer);

// Get current balance
long long wabisabi_issuer_get_balance(const CredentialIssuer* issuer);

// Handle credential request (to be implemented)
// void* wabisabi_issuer_handle_request(
//     CredentialIssuer* issuer,
//     const void* request,
//     Random* random,
//     FFIError* error
// );
```

### Client API

```c
// Create client with coordinator's public parameters
WabiSabiClient* wabisabi_client_create(
    const FFIGroupElement* coordinator_params_cw,
    const FFIGroupElement* coordinator_params_i,
    FFIError* error
);

// Destroy client
void wabisabi_client_destroy(WabiSabiClient* client);

// Create request for zero-value credentials (bootstrap)
void* wabisabi_client_create_zero_request(
    const WabiSabiClient* client,
    Random* random,
    FFIScalarArray* randomness_out,  // Output: secret randomness
    FFIError* error
);

// Create request for real-value credentials (to be fully implemented)
// void* wabisabi_client_create_request(
//     const WabiSabiClient* client,
//     const FFIAmountArray* amounts,
//     const void* credentials,
//     Random* random,
//     FFIScalarArray* randomness_out,
//     FFIError* error
// );
```

### Memory Management

```c
// Free scalar array
void wabisabi_free_scalar_array(FFIScalarArray array);

// Free group element array
void wabisabi_free_group_element_array(FFIGroupElementArray array);
```

### Utilities

```c
// Get library version
const char* wabisabi_version(void);
```

## Usage Example

```c
#include <stdio.h>
#include "nwabisabi.h"

int main() {
    FFIError error;

    // 1. Create RNG
    Random* random = wabisabi_random_create(&error);
    if (!random) {
        fprintf(stderr, "Failed to create RNG: %d\n", error);
        return 1;
    }

    // 2. Create issuer (coordinator)
    FFIGroupElement cw, i;
    CredentialIssuer* issuer = wabisabi_issuer_create_random(
        random,
        1000000,  // Initial balance
        &cw,
        &i,
        &error
    );

    if (!issuer) {
        fprintf(stderr, "Failed to create issuer: %d\n", error);
        wabisabi_random_destroy(random);
        return 1;
    }

    printf("Issuer balance: %lld\n", wabisabi_issuer_get_balance(issuer));

    // 3. Create client with coordinator's public parameters
    WabiSabiClient* client = wabisabi_client_create(&cw, &i, &error);
    if (!client) {
        fprintf(stderr, "Failed to create client: %d\n", error);
        wabisabi_issuer_destroy(issuer);
        wabisabi_random_destroy(random);
        return 1;
    }

    // 4. Client creates zero-value credential request
    FFIScalarArray randomness;
    void* request = wabisabi_client_create_zero_request(
        client,
        random,
        &randomness,
        &error
    );

    if (!request) {
        fprintf(stderr, "Failed to create request: %d\n", error);
    } else {
        printf("Created zero request with %zu randomness values\n",
               randomness.length);
        wabisabi_free_scalar_array(randomness);
    }

    // 5. Clean up
    wabisabi_client_destroy(client);
    wabisabi_issuer_destroy(issuer);
    wabisabi_random_destroy(random);

    return 0;
}
```

## Compilation

### Linux/macOS

```bash
# Using dynamic library
gcc -o example example.c -L target/release -lnwabisabi -lpthread -ldl -lm
LD_LIBRARY_PATH=target/release ./example

# Using static library
gcc -o example example.c target/release/libnwabisabi.a -lpthread -ldl -lm
./example
```

### Windows

```cmd
cl example.c /I include /link target\release\nwabisabi.dll.lib
```

## Safety Considerations

All FFI functions are marked as `unsafe` in Rust. Callers must ensure:

1. **Non-null pointers**: Unless explicitly documented as optional, all pointers must be non-null
2. **Proper alignment**: Pointers must be properly aligned for their type
3. **Valid lifetimes**: Pointers must point to valid memory for the duration of the call
4. **No use-after-free**: Objects must not be used after being destroyed
5. **Thread safety**: Unless documented as thread-safe, objects should not be shared between threads

### Error Handling

Most functions accept an `FFIError* error` output parameter. Always check:
- Return value is non-null (for pointer-returning functions)
- Error code is `Success` (0)

Example:
```c
FFIError error;
Random* random = wabisabi_random_create(&error);
if (!random || error != Success) {
    // Handle error
}
```

### Memory Management

Objects created with `_create` functions MUST be freed with corresponding `_destroy` functions:

```c
Random* random = wabisabi_random_create(&error);
// ... use random ...
wabisabi_random_destroy(random);  // Required!
```

Arrays returned by functions must be freed with `wabisabi_free_*_array` functions:

```c
FFIScalarArray array;
// ... get array from function ...
wabisabi_free_scalar_array(array);  // Required!
```

## Language Bindings

The C FFI can be used to create bindings for other languages:

### Python (using ctypes)

```python
from ctypes import *

lib = CDLL("target/release/libnwabisabi.so")

class FFIError(c_int):
    Success = 0
    InvalidGroupElement = 1
    # ...

lib.wabisabi_random_create.restype = c_void_p
lib.wabisabi_random_create.argtypes = [POINTER(FFIError)]

error = FFIError()
random = lib.wabisabi_random_create(byref(error))
```

### Node.js (using ffi-napi)

```javascript
const ffi = require('ffi-napi');

const lib = ffi.Library('target/release/libnwabisabi', {
  'wabisabi_random_create': ['pointer', ['pointer']],
  'wabisabi_random_destroy': ['void', ['pointer']],
  // ...
});

const error = Buffer.alloc(4);
const random = lib.wabisabi_random_create(error);
```

### Go (using cgo)

```go
// #cgo LDFLAGS: -L${SRCDIR}/target/release -lnwabisabi
// #include "include/nwabisabi.h"
import "C"
import "unsafe"

func CreateRandom() unsafe.Pointer {
    var error C.FFIError
    random := C.wabisabi_random_create(&error)
    if random == nil {
        panic("Failed to create random")
    }
    return random
}
```

## Current Limitations

The FFI layer is functional but has some limitations:

1. Complete request/response cycle not fully exposed
2. Credential handling functions need expansion
3. Proof verification details not exposed
4. No async/callback support

These will be addressed in future updates.

## Further Reading

- [WabiSabi Paper](https://eprint.iacr.org/2021/206) - Protocol specification
- [Rust Documentation](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) - Unsafe Rust and FFI
- [cbindgen](https://github.com/eqrion/cbindgen) - C header generation tool
