{
  description = "NWabiSabi - Rust implementation of the WabiSabi anonymous credential protocol";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Rust toolchain configuration
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
          targets = [ "x86_64-unknown-linux-gnu" ];
        };

        # Crane library for building Rust projects
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Source filtering - only include Rust source files
        src = craneLib.cleanCargoSource (craneLib.path ./.);

        # Common build arguments
        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = with pkgs; [
            openssl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            # macOS-specific dependencies
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate
        nwabisabi = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;

          # Additional outputs
          outputs = [ "out" "dev" ];

          postInstall = ''
            # Create dev output with headers if cbindgen is available
            mkdir -p $dev/include

            # Copy static library to both outputs
            if [ -f "target/release/libnwabisabi.a" ]; then
              mkdir -p $out/lib
              cp target/release/libnwabisabi.a $out/lib/
            fi
          '';
        });

        # Run tests
        nwabisabi-tests = craneLib.cargoTest (commonArgs // {
          inherit cargoArtifacts;
          cargoTestExtraArgs = "-- --nocapture";
        });

        # Run clippy
        nwabisabi-clippy = craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        });

        # Check formatting
        nwabisabi-fmt = craneLib.cargoFmt {
          inherit src;
        };

        # Generate documentation
        nwabisabi-doc = craneLib.cargoDoc (commonArgs // {
          inherit cargoArtifacts;
          cargoDocExtraArgs = "--no-deps --document-private-items";
        });

      in
      {
        # Outputs
        packages = {
          default = nwabisabi;
          nwabisabi = nwabisabi;
          tests = nwabisabi-tests;
          clippy = nwabisabi-clippy;
          fmt = nwabisabi-fmt;
          doc = nwabisabi-doc;
        };

        # Checks - run with `nix flake check`
        checks = {
          inherit nwabisabi nwabisabi-tests nwabisabi-clippy nwabisabi-fmt;
        };

        # Apps - run with `nix run .#<app>`
        apps = {
          # Run tests
          test = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "test-nwabisabi" ''
              ${rustToolchain}/bin/cargo test --color=always
            '';
          };

          # Run benchmarks
          bench = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "bench-nwabisabi" ''
              ${rustToolchain}/bin/cargo bench
            '';
          };

          # # Generate C headers (requires cbindgen to be installed separately)
          # cbindgen = flake-utils.lib.mkApp {
          #   drv = pkgs.writeShellScriptBin "generate-headers" ''
          #     mkdir -p include
          #     cbindgen \
          #       --config cbindgen.toml \
          #       --output include/nwabisabi.h
          #     echo "Generated C headers in include/nwabisabi.h"
          #   '';
          # };
        };

        # Development shell
        devShells.default = craneLib.devShell {
          # Inherit inputs from checks
          checks = self.checks.${system};

          packages = with pkgs; [
            # Rust toolchain (already includes cargo, rustc, etc.)
            rustToolchain

            # Additional Rust tools
            cargo-edit          # cargo add, cargo rm, cargo upgrade
            cargo-watch         # cargo watch
            cargo-expand        # cargo expand (macro expansion)
            cargo-flamegraph    # Performance profiling
            cargo-bloat         # Binary size profiler
            cargo-udeps         # Find unused dependencies
            cargo-outdated      # Check for outdated dependencies
            bacon               # Background rust code checker

            # C development (for FFI)
            gcc
            clang
            # cbindgen       # C header generation (install separately if needed)
            gdb                 # Debugger
            valgrind            # Memory leak detection

            # Build tools
            pkg-config
            openssl

            # Documentation
            mdbook              # For writing documentation

            # Version control
            git

            # Editor tools
            nil                 # Nix LSP
            nixpkgs-fmt         # Nix formatter
          ];

          # Environment variables
          shellHook = ''
            echo "🦀 NWabiSabi Development Environment"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo ""
            echo "📦 Available commands:"
            echo "  cargo build          - Build the library"
            echo "  cargo test           - Run tests"
            echo "  cargo clippy         - Lint code"
            echo "  cargo fmt            - Format code"
            echo "  cargo doc --open     - Generate and open docs"
            echo "  cargo bench          - Run benchmarks"
            echo ""
            echo "  nix run .#cbindgen   - Generate C headers"
            echo "  nix flake check      - Run all checks"
            echo ""
            echo "🔧 Useful cargo-watch commands:"
            echo "  cargo watch -x test  - Auto-run tests on change"
            echo "  cargo watch -x check - Auto-check on change"
            echo ""
            echo "📚 Documentation:"
            echo "  See README.md for usage examples"
            echo "  See FFI_GUIDE.md for C FFI documentation"
            echo "  See IMPLEMENTATION_STATUS.md for progress"
            echo ""

            # Set up environment for development
            export RUST_BACKTRACE=1
            export RUST_LOG=debug
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl ]}:$LD_LIBRARY_PATH"

            # Create directories
            mkdir -p include target
          '';

          # Make rust-analyzer work
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };

        # Default development shell (alias)
        devShell = self.devShells.${system}.default;

        # Formatter for `nix fmt`
        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
