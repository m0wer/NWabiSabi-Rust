# NWabiSabi - Rust Implementation

Rust implementation of the WabiSabi anonymous credential protocol, ported from the C# version.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

WabiSabi is an anonymous credential protocol based on keyed-verification anonymous credentials (KVAC). This is a complete Rust implementation with:

- ✅ Full cryptographic primitives using secp256k1
- ✅ Zero-knowledge proof system with Fiat-Shamir transformation
- ✅ Credential issuance and presentation
- ✅ Client and issuer APIs
- ✅ C FFI for language interoperability
- ✅ 99 passing tests

## Project Status: 87.5% Complete

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for detailed progress tracking.

### ✅ Completed Phases (7/8)

1. **Cryptographic Primitives** - 850 LOC, 19 tests
2. **Strobe & Transcript** - 400 LOC, 17 tests
3. **Zero-Knowledge Proofs** - 910 LOC, 27 tests
4. **Credentials & MAC** - 820 LOC, 24 tests
5. **Request/Response Protocol** - 257 LOC, 4 tests
6. **Client & Issuer APIs** - 770 LOC, 6 tests
7. **FFI Layer** - 680 LOC, 2 tests

**Total: 4,687 lines of production code, 99 tests passing**

### 🚧 Remaining Work

8. **Testing & Optimization**
   - Port remaining C# test suites
   - Property-based testing
   - Performance profiling
   - Security audit

## Quick Start

### Prerequisites

**Option 1: Using Nix (Recommended)**
- Nix with flakes enabled (see [NIX_USAGE.md](NIX_USAGE.md))

**Option 2: Traditional Rust**
- Rust 1.70+ (install from https://rustup.rs/)
- C compiler (for FFI examples)
- cbindgen (optional, for C header generation)

### Building

**With Nix (Reproducible Builds):**
```bash
# Enter development environment
nix develop

# Or build directly
nix build

# Run tests
nix run .#test

# Run all checks (build, test, lint, format)
nix flake check
```

**With Cargo:**
```bash
# Clone and build
cd nwabisabi
cargo build --release

# Run tests
cargo test

# Generate C headers (requires cbindgen)
cbindgen --config cbindgen.toml --output include/nwabisabi.h
```

**With Make (convenience wrapper):**
```bash
# Show all available targets
make help

# Build and test
make build
make test

# Nix commands
make nix-build
make nix-check

# Generate C headers
make headers

# Install system-wide
make install
```

See [NIX_USAGE.md](NIX_USAGE.md) for complete Nix documentation.

## Usage

### Rust API

```rust
use nwabisabi::{
    CredentialIssuer, WabiSabiClient,
    crypto::{CredentialIssuerSecretKey, randomness::SecureRandom},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut random = SecureRandom::new();

    // 1. Create issuer (coordinator)
    let secret_key = CredentialIssuerSecretKey::random(&mut random)?;
    let params = secret_key.compute_credential_issuer_parameters()?;
    let issuer = CredentialIssuer::new(secret_key, 1_000_000)?;

    // 2. Create client
    let client = WabiSabiClient::new(params);

    // 3. Client creates zero-value credential request
    let (request, randomness) = client.create_request_for_zero_amount(&mut random)?;

    // 4. Issuer handles request
    let response = issuer.handle_request(&request, &mut random)?;

    // 5. Client handles response
    let credentials = client.handle_response(&response, &randomness, &request)?;

    println!("Issued {} credentials", credentials.len());
    Ok(())
}
```

### C FFI

```c
#include "nwabisabi.h"

int main() {
    FFIError error;

    // Create RNG
    Random* random = wabisabi_random_create(&error);

    // Create issuer
    FFIGroupElement cw, i;
    CredentialIssuer* issuer = wabisabi_issuer_create_random(
        random, 1000000, &cw, &i, &error);

    // Create client
    WabiSabiClient* client = wabisabi_client_create(&cw, &i, &error);

    // Create zero request
    FFIScalarArray randomness;
    void* request = wabisabi_client_create_zero_request(
        client, random, &randomness, &error);

    // Clean up
    wabisabi_free_scalar_array(randomness);
    wabisabi_client_destroy(client);
    wabisabi_issuer_destroy(issuer);
    wabisabi_random_destroy(random);

    return 0;
}
```

See [FFI_GUIDE.md](FFI_GUIDE.md) for complete FFI documentation.

## Architecture

### Module Organization

```
src/
├── crypto/              # Cryptographic primitives
│   ├── scalar.rs        # Scalar wrapper
│   ├── group_element.rs # Point with lazy affine evaluation
│   ├── generators.rs    # Protocol generators
│   ├── mac.rs           # Message Authentication Code
│   ├── issuer_key.rs    # Secret/public key pairs
│   └── randomness/      # RNG abstractions
├── zero_knowledge/      # ZK proof system
│   ├── transcript.rs    # Fiat-Shamir transformation
│   ├── proof_system.rs  # Sigma protocols
│   ├── credential.rs    # Credential structure
│   └── linear_relation/ # Linear equation proofs
├── credential_requesting/ # Protocol messages
│   ├── issuance_request.rs
│   ├── credentials_request.rs
│   └── credentials_response.rs
├── wabisabi_client.rs   # Client API
├── credential_issuer.rs # Coordinator API
└── ffi/                 # C Foreign Function Interface
    ├── types.rs         # FFI-safe types
    └── exports.rs       # C API exports
```

### Key Design Decisions

1. **Lazy Affine Evaluation**
   ```rust
   pub struct GroupElement {
       compressed: [u8; 33],
       public_key: OnceCell<secp256k1::PublicKey>,
   }
   ```
   Stores compressed representation, computes affine only when needed (serialization, comparison).

2. **Thread-Safe State Management**
   ```rust
   pub struct CredentialIssuer {
       balance: Arc<AtomicI64>,
       serial_numbers: Arc<Mutex<HashSet<Vec<u8>>>>,
       // ...
   }
   ```
   Uses atomic operations for balance, mutex for serial number tracking.

3. **Error Handling**
   ```rust
   pub type Result<T> = std::result::Result<T, WabiSabiError>;
   ```
   All fallible operations return `Result` with descriptive errors.

4. **FFI Safety**
   - Opaque pointers for complex types
   - C-compatible error codes
   - Explicit memory management functions

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| secp256k1 | 0.29 | Elliptic curve cryptography |
| strobe-rs | 0.8 | Strobe-128 protocol (Fiat-Shamir) |
| serde | 1.0 | Serialization |
| thiserror | 1.0 | Error handling |
| lazy_static | 1.5 | Static initialization |
| rand | 0.8 | Random number generation |

## Testing

```bash
# Run all tests
cargo test

# Run specific test module
cargo test --test credential_tests

# Run with output
cargo test -- --nocapture

# Run benchmarks (requires nightly)
cargo +nightly bench
```

### Test Coverage

- Unit tests in each module (`#[cfg(test)]`)
- Integration tests in `tests/` directory
- 99 tests covering all major components
- Property-based tests planned for Phase 8

## Performance

Preliminary benchmarks (vs C# implementation):

| Operation | Rust | C# | Ratio |
|-----------|------|-----|-------|
| Scalar multiplication | TBD | TBD | TBD |
| Proof generation | TBD | TBD | TBD |
| Proof verification | TBD | TBD | TBD |
| Full request cycle | TBD | TBD | TBD |

*Benchmarking planned for Phase 8*

## Security Notes

⚠️ **This implementation has not been audited.** Do not use in production without:

1. Comprehensive security audit
2. Constant-time operation verification
3. Side-channel attack analysis
4. Formal verification of critical paths

The implementation follows the [WabiSabi paper](https://eprint.iacr.org/2021/206) specification but requires professional review.

## Contributing

Contributions are welcome! Areas needing work:

- [ ] Complete test porting from C# (59 test files)
- [ ] Property-based tests (QuickCheck/proptest)
- [ ] Performance optimization
- [ ] Additional language bindings (Python, Node.js, Go)
- [ ] Documentation improvements
- [ ] Security audit

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for detailed task list.

## Critical Files Mapping

| C# File | Rust Module | Status | LOC |
|---------|-------------|--------|-----|
| `GroupElement.cs` | `crypto/group_element.rs` | ✅ Complete | 280 |
| `ProofSystem.cs` | `zero_knowledge/proof_system.rs` | ✅ Complete | 160 |
| `CredentialIssuer.cs` | `credential_issuer.rs` | ✅ Complete | 320 |
| `WabiSabiClient.cs` | `wabisabi_client.rs` | ✅ Complete | 450 |
| `Strobe.cs` | Wraps `strobe-rs` | ✅ Complete | 150 |
| `Generators.cs` | `crypto/generators.rs` | ✅ Complete | 150 |

## Documentation

### Project Documentation
- [QUICKSTART.md](QUICKSTART.md) - Get started in 5 minutes
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - Detailed progress tracking
- [FFI_GUIDE.md](FFI_GUIDE.md) - Complete C FFI documentation

### Build & Development
- [NIX_USAGE.md](NIX_USAGE.md) - Complete Nix flake guide
- [NIX_SUMMARY.md](NIX_SUMMARY.md) - Quick Nix reference
- [Makefile](Makefile) - Convenient build targets (`make help`)

### Protocol & API
- [WabiSabi Paper](https://eprint.iacr.org/2021/206) - Protocol specification
- API docs: `cargo doc --open`

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Original C# implementation: [zkSNACKs/WabiSabi](https://github.com/zkSNACKs/WabiSabi)
- WabiSabi protocol: Fuchsbauer et al., 2021
- secp256k1 library: Bitcoin Core contributors
- strobe-rs: Isis Lovecruft and contributors

## References

1. Fuchsbauer, G., Orrù, M., & Seurin, Y. (2021). *Aggregate Cash Systems: A Cryptographic Investigation of Mimblewimble*. IACR ePrint 2021/206.
2. [WabiSabi: Centrally Coordinated CoinJoins with Variable Amounts](https://eprint.iacr.org/2021/206)
3. [secp256k1 elliptic curve](https://www.secg.org/sec2-v2.pdf)
4. [Strobe protocol](https://strobe.sourceforge.io/)
