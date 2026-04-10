# Nix Flake Summary

Complete overview of the Nix flake configuration for NWabiSabi.

## 📋 Features

✅ **Reproducible Builds** - Same build everywhere, every time
✅ **Development Shell** - Complete dev environment with one command
✅ **CI/CD Ready** - GitHub Actions workflow included
✅ **Multi-Platform** - Linux, macOS support out of the box
✅ **Cargo Integration** - Uses crane for efficient Rust builds
✅ **Cached Builds** - Incremental builds, dependency caching
✅ **Quality Checks** - Automated formatting, linting, testing
✅ **Documentation** - Auto-generated docs
✅ **C FFI Support** - Includes cbindgen for header generation

## 🎯 Quick Reference

### Essential Commands

| Command | Description |
|---------|-------------|
| `nix develop` | Enter development shell |
| `nix build` | Build the library |
| `nix flake check` | Run all checks |
| `nix run .#test` | Run tests |
| `nix run .#cbindgen` | Generate C headers |

### Development Shell Tools

When you run `nix develop`, you get:

**Rust Toolchain:**
- rustc (Rust compiler)
- cargo (build tool)
- clippy (linter)
- rust-analyzer (LSP)
- rust-src (source code for completion)

**Cargo Tools:**
- cargo-watch - Auto-rebuild on file changes
- cargo-edit - cargo add/rm/upgrade commands
- cargo-expand - Macro expansion
- cargo-flamegraph - Performance profiling
- cargo-bloat - Binary size analysis
- cargo-udeps - Find unused dependencies
- cargo-outdated - Check for outdated deps
- bacon - Background code checker

**C Development:**
- gcc - C compiler
- clang - Alternative C compiler
- cbindgen - C header generation
- gdb - Debugger
- valgrind - Memory leak detection

**Build Tools:**
- pkg-config
- openssl

**Documentation:**
- mdbook - Documentation generator

**Editor Tools:**
- nil - Nix LSP server
- nixpkgs-fmt - Nix code formatter

## 📦 Flake Outputs

### Packages (`nix build .#<name>`)

```
.#default          Main library (same as .#nwabisabi)
.#nwabisabi        The NWabiSabi library
.#tests            Test suite
.#clippy           Clippy checks
.#fmt              Format checks
.#doc              Documentation
```

### Apps (`nix run .#<name>`)

```
.#test             Run the test suite
.#bench            Run benchmarks
.#cbindgen         Generate C headers
```

### Checks (`nix flake check`)

Runs all of:
- Build check (library builds successfully)
- Test check (all tests pass)
- Clippy check (no linter warnings)
- Format check (code is properly formatted)

## 🏗️ Build System Architecture

### Crane Integration

The flake uses [crane](https://github.com/ipetkov/crane) for efficient Rust builds:

```
1. Build dependencies (buildDepsOnly)
   ↓
   Cached separately from your code
   ↓
2. Build your code (buildPackage)
   ↓
   Only rebuilds when source changes
   ↓
3. Run tests (cargoTest)
```

Benefits:
- **Fast rebuilds**: Dependencies cached separately
- **CI friendly**: Can cache dependency builds
- **Incremental**: Only changed files recompile

### Rust Overlay

Uses [rust-overlay](https://github.com/oxalica/rust-overlay) for:
- Latest stable Rust toolchain
- Multiple Rust versions (stable, beta, nightly)
- Cross-compilation targets
- Rust components (clippy, rust-analyzer, etc.)

## 🔧 Customization

### Using Nightly Rust

Edit `flake.nix`:
```nix
rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
  extensions = [ "rust-src" "rust-analyzer" "clippy" ];
};
```

### Pinning Rust Version

```nix
rustToolchain = pkgs.rust-bin.stable."1.75.0".default.override {
  # ...
};
```

### Adding Cross-Compilation Targets

```nix
rustToolchain = pkgs.rust-bin.stable.latest.default.override {
  extensions = [ "rust-src" "rust-analyzer" "clippy" ];
  targets = [
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"    # ARM64 Linux
    "x86_64-apple-darwin"           # macOS Intel
    "aarch64-apple-darwin"          # macOS M1/M2
    "x86_64-pc-windows-gnu"         # Windows
  ];
};
```

### Adding Development Tools

Edit the `devShells.default` section:
```nix
packages = with pkgs; [
  rustToolchain
  # Add your tools here
  your-favorite-tool
];
```

## 🚀 CI/CD Integration

### GitHub Actions (Included)

The provided `.github/workflows/ci.yml` runs:
1. ✅ Nix flake checks (reproducible)
2. ✅ Multi-platform cargo builds (Linux, macOS, Windows)
3. ✅ Documentation generation
4. ✅ Code coverage (optional)
5. ✅ Security audit
6. ✅ Benchmarks (on main branch)

### GitLab CI Example

```yaml
image: nixos/nix:latest

before_script:
  - echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

stages:
  - check
  - build
  - test

check:
  stage: check
  script:
    - nix flake check

build:
  stage: build
  script:
    - nix build
  artifacts:
    paths:
      - result/

test:
  stage: test
  script:
    - nix build .#tests
```

## 📊 Performance

### Build Times (Approximate)

| Operation | Cold (no cache) | Warm (cached) |
|-----------|----------------|---------------|
| Enter shell | 5-10 min | < 1 sec |
| Build deps | 10-15 min | < 1 sec |
| Build code | 2-5 min | 10-30 sec |
| Run tests | 1-2 min | 10-30 sec |
| Full check | 15-20 min | 1-2 min |

*Cold = first time, Warm = with Nix cache*

### Caching Strategy

Nix caches at multiple levels:
1. **Binary cache** (cache.nixos.org) - Pre-built packages
2. **Dependency builds** - Cargo dependencies cached separately
3. **Source builds** - Only changed files recompile

To share your cache:
```bash
# Set up Cachix (optional)
cachix use nwabisabi
```

## 🔐 Security

### Flake Lock

The `flake.lock` pins exact versions:
```bash
# View locked inputs
nix flake metadata

# Update all inputs
nix flake update

# Update specific input
nix flake lock --update-input rust-overlay
```

### Reproducibility

Same `flake.lock` = Same build everywhere:
- ✅ Deterministic dependencies
- ✅ Pinned tool versions
- ✅ Transparent dependency tree
- ✅ No "works on my machine" issues

## 🌍 Cross-Platform Support

### Linux
- ✅ Native support
- ✅ All features work

### macOS
- ✅ Native support
- ✅ Includes Darwin frameworks

### Windows
- ⚠️ WSL2 recommended
- ⚠️ Native Windows Nix support is experimental

## 🎓 Learning Resources

### Nix Flakes
- [Nix Flakes Manual](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html)
- [Zero to Nix](https://zero-to-nix.com/)
- [Nix Pills](https://nixos.org/guides/nix-pills/)

### Rust + Nix
- [Crane Documentation](https://crane.dev/)
- [rust-overlay README](https://github.com/oxalica/rust-overlay)
- [Nix Community Rust Guide](https://nix.dev/tutorials/cross-compilation)

### Development
- [direnv](https://direnv.net/) - Auto-load environments
- [Cachix](https://cachix.org/) - Binary cache hosting
- [devenv](https://devenv.sh/) - Alternative to flakes

## 📝 Best Practices

### Development Workflow

1. **Use `nix develop` for consistency**
   ```bash
   nix develop
   # Now use cargo normally
   ```

2. **Commit `flake.lock`**
   - Ensures reproducibility
   - Pin exact dependency versions
   - Update explicitly with `nix flake update`

3. **Use direnv for convenience**
   ```bash
   echo "use flake" > .envrc
   direnv allow
   # Automatic environment on cd!
   ```

4. **Cache in CI**
   ```yaml
   - uses: cachix/cachix-action@v12
     with:
       name: your-cache-name
   ```

### Production Builds

```bash
# Build optimized release
nix build

# Extract artifacts
cp result/lib/libnwabisabi.a /path/to/deploy/

# Verify reproducibility
nix build --rebuild
shasum result/lib/libnwabisabi.a
```

## 🐛 Common Issues

### Issue: "error: experimental feature 'flakes' is disabled"
**Solution:**
```bash
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Issue: "error: unable to checkout ...'
**Solution:** Ensure internet connection, or:
```bash
nix flake update  # Refresh inputs
```

### Issue: Slow first build
**Solution:** This is normal. Nix builds are cached:
- First build: 10-20 minutes
- Subsequent builds: 1-2 minutes

### Issue: "error: not a flake"
**Solution:** Ensure you're in the right directory:
```bash
cd /path/to/nwabisabi
nix flake show  # Verify flake exists
```

## 📈 Monitoring

### Check what's building
```bash
nix build -L  # Live build logs
```

### See dependency tree
```bash
nix why-depends result nixpkgs#rustc
```

### Profile build
```bash
nix build --profile ./profile
nix profile diff-closures $(ls -d profile-* | head -1) ./profile
```

## 🎉 Summary

The Nix flake provides:
- ✅ Complete, reproducible development environment
- ✅ Efficient, cached builds
- ✅ CI/CD ready
- ✅ Multi-platform support
- ✅ Quality checks built-in
- ✅ Easy to customize
- ✅ Production-ready artifacts

**One command to rule them all:**
```bash
nix develop  # and you're ready to code! 🚀
```
