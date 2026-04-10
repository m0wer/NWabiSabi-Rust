# NWabiSabi Quick Start Guide

Get up and running with NWabiSabi in 5 minutes!

## 🚀 Fastest Way (Using Nix)

```bash
# 1. Enter the project directory
cd nwabisabi

# 2. Enter development environment
nix develop

# 3. Build and test
cargo build --release
cargo test

# Done! 🎉
```

## 📦 Traditional Setup

```bash
# 1. Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Build
cargo build --release

# 3. Test
cargo test
```

## 🎯 Common Tasks

### Run the Full Test Suite
```bash
# With Nix
nix run .#test

# With cargo
cargo test

# With make
make test
```

### Generate C Headers for FFI
```bash
# With Nix
nix run .#cbindgen

# With cargo + cbindgen
cbindgen --config cbindgen.toml --output include/nwabisabi.h

# With make
make headers
```

### Run All Quality Checks
```bash
# With Nix (recommended)
nix flake check

# With cargo
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test

# With make
make check
```

### Build for Production
```bash
# With Nix (reproducible)
nix build
ls -l result/lib/libnwabisabi.a

# With cargo
cargo build --release
ls -l target/release/libnwabisabi.a
```

## 📝 Your First Program

### Rust Example

Create `examples/my_example.rs`:

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

    println!("✓ Issuer created with balance: {}", issuer.balance());

    // 2. Create client
    let client = WabiSabiClient::new(params);
    println!("✓ Client created");

    // 3. Client creates zero-value credential request
    let (request, randomness) = client.create_request_for_zero_amount(&mut random)?;
    println!("✓ Created credential request");

    // 4. Issuer handles request
    let response = issuer.handle_request(&request, &mut random)?;
    println!("✓ Issuer processed request");

    // 5. Client handles response
    let credentials = client.handle_response(&response, &randomness, &request)?;
    println!("✓ Received {} credentials", credentials.len());

    Ok(())
}
```

Run it:
```bash
cargo run --example my_example
```

### C Example

Create `my_example.c`:

```c
#include <stdio.h>
#include "include/nwabisabi.h"

int main() {
    FFIError error;

    // Create RNG
    Random* random = wabisabi_random_create(&error);
    if (!random) {
        fprintf(stderr, "Failed to create RNG\n");
        return 1;
    }

    // Create issuer
    FFIGroupElement cw, i;
    CredentialIssuer* issuer = wabisabi_issuer_create_random(
        random, 1000000, &cw, &i, &error);

    printf("Issuer balance: %lld\n",
           wabisabi_issuer_get_balance(issuer));

    // Clean up
    wabisabi_issuer_destroy(issuer);
    wabisabi_random_destroy(random);

    printf("Success!\n");
    return 0;
}
```

Compile and run:
```bash
# Generate headers first
make headers

# Build
gcc -o my_example my_example.c \
    -I include \
    -L target/release \
    -lnwabisabi \
    -lpthread -ldl -lm

# Run
LD_LIBRARY_PATH=target/release ./my_example
```

## 🛠️ Development Workflow

### Option 1: Nix Development Shell (Recommended)

```bash
# Enter once
nix develop

# Then use cargo as normal
cargo check       # Fast type checking
cargo test        # Run tests
cargo build       # Build
cargo clippy      # Lint

# Or use cargo-watch for auto-rebuild
cargo watch -x test
```

### Option 2: Traditional Cargo

```bash
# Check types (fast)
cargo check

# Run tests on change
cargo install cargo-watch
cargo watch -x test

# Format code
cargo fmt

# Lint
cargo clippy
```

### Option 3: Using Make

```bash
# See all targets
make help

# Common workflows
make build test
make check
make doc
```

## 📚 Next Steps

- **Read the API documentation**: `cargo doc --open`
- **Explore FFI usage**: See [FFI_GUIDE.md](FFI_GUIDE.md)
- **Learn about Nix**: See [NIX_USAGE.md](NIX_USAGE.md)
- **Check implementation status**: See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)
- **Understand the protocol**: Read the [WabiSabi paper](https://eprint.iacr.org/2021/206)

## 🐛 Troubleshooting

### "cargo: command not found"

Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### "experimental Nix feature 'flakes' is disabled"

Enable flakes:
```bash
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Tests failing

Clean and rebuild:
```bash
cargo clean
cargo build
cargo test
```

### Linker errors with FFI

Make sure you have a C compiler:
```bash
# Ubuntu/Debian
sudo apt install build-essential

# macOS
xcode-select --install

# With Nix
nix develop  # Already includes gcc
```

## 💡 Tips

1. **Use `cargo check` for fast feedback** while developing (no code generation)
2. **Use `cargo clippy`** to catch common mistakes
3. **Use `cargo doc --open`** to browse documentation locally
4. **Use Nix for reproducible builds** in CI/CD
5. **Use direnv** for automatic environment loading with Nix

## 🤝 Getting Help

- Check the [README.md](README.md) for detailed information
- Review test files in `tests/` for usage examples
- Open an issue on GitHub for bugs or questions
- Read the inline documentation: `cargo doc --open`

## ⚡ Performance Tips

```bash
# Use release builds for benchmarking
cargo build --release
cargo bench

# Profile with flamegraph
cargo install flamegraph
cargo flamegraph --bin <binary>

# Check binary size
cargo install cargo-bloat
cargo bloat --release
```

Happy coding! 🦀
