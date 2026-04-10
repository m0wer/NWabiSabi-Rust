.PHONY: help build test check clean install doc bench headers dev-shell nix-build nix-test nix-check

# Default target
help:
	@echo "NWabiSabi - Available targets:"
	@echo ""
	@echo "  Nix targets (recommended):"
	@echo "    nix-build     - Build with Nix (reproducible)"
	@echo "    nix-test      - Run tests with Nix"
	@echo "    nix-check     - Run all checks (build, test, clippy, fmt)"
	@echo "    dev-shell     - Enter Nix development shell"
	@echo "    headers       - Generate C headers with cbindgen"
	@echo ""
	@echo "  Cargo targets:"
	@echo "    build         - Build with cargo"
	@echo "    test          - Run tests with cargo"
	@echo "    check         - Run clippy and fmt checks"
	@echo "    bench         - Run benchmarks"
	@echo "    doc           - Generate documentation"
	@echo "    clean         - Clean build artifacts"
	@echo ""
	@echo "  Installation:"
	@echo "    install       - Install library (requires sudo)"
	@echo ""

# Nix targets
nix-build:
	nix build

nix-test:
	nix run .#test

nix-check:
	nix flake check

dev-shell:
	nix develop

headers:
	@mkdir -p include
	nix run .#cbindgen

# Cargo targets
build:
	cargo build --release

test:
	cargo test

check:
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings
	cargo test

bench:
	cargo bench

doc:
	cargo doc --no-deps --open

clean:
	cargo clean
	rm -rf result result-* include/nwabisabi.h

# Installation
install: build headers
	@echo "Installing to /usr/local..."
	sudo mkdir -p /usr/local/lib /usr/local/include
	sudo cp target/release/libnwabisabi.a /usr/local/lib/
	sudo cp include/nwabisabi.h /usr/local/include/
	@echo "Installation complete!"
	@echo ""
	@echo "To use from C:"
	@echo "  gcc example.c -lnwabisabi -lpthread -ldl -lm"

# Development helpers
format:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

watch-test:
	cargo watch -x test

watch-check:
	cargo watch -x check

# FFI example
ffi-example: headers
	@mkdir -p target/examples
	gcc -o target/examples/ffi_example examples/ffi_example.c \
		-I include \
		-L target/release \
		-lnwabisabi \
		-lpthread -ldl -lm
	@echo "Built target/examples/ffi_example"
	@echo "Run with: LD_LIBRARY_PATH=target/release target/examples/ffi_example"

# Quick CI-like check
ci: clean
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings
	cargo build --release
	cargo test
	@echo "✓ All CI checks passed!"
