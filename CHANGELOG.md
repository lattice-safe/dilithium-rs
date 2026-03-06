# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-07

### Added
- **SIMD acceleration**: AVX2 (x86_64) and NEON (AArch64) NTT behind `simd` feature
- **Multi-vector KAT**: 100 iterations × 3 modes validated against C reference
- **Fuzzing**: 3 fuzz targets (`fuzz_sign_verify`, `fuzz_unpack_sig`, `fuzz_from_bytes`), 41M+ runs, 0 crashes
- **Criterion benchmarks**: keygen/sign/verify × 3 modes
- **SECURITY.md**: responsible disclosure policy and scope of guarantees
- **Examples**: `keygen`, `sign_verify`, `serialize` programs
- **`js` feature**: `getrandom/js` for WASM browser targets
- **`simd` feature**: opt-in SIMD NTT acceleration
- GitHub Actions CI (7 jobs: test, clippy, fmt, docs, WASM, no_std, cargo-deny)
- `deny.toml` for license and advisory auditing
- Cross-validated KAT sig hashes against C reference binary output

### Changed
- `getrandom` now optional (activated by `std` feature) for WASM/no_std compatibility
- Gated `generate()`, `sign()`, `sign_prehash()` behind `getrandom` feature
- Enhanced crate-level docs with feature flags table and platform matrix
- README: added benchmark comparison table vs C reference
- 73 tests (was 65)

### Fixed
- Zeroize keying material (`seedbuf`, `expanded`, `rhoprime`, `key`) in sign.rs
- KAT signature hashes now match C reference (was using `rnd=0` instead of stream rnd)

### Security
- `cargo-semver-checks`: 196 checks passed, 0 breaking changes vs v0.1.0

## [0.1.0] - 2026-03-06

### Added
- Pure Rust implementation of ML-DSA (FIPS 204) / CRYSTALS-Dilithium
- Support for all three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87
- Pure ML-DSA signing and verification (§6.1)
- HashML-DSA pre-hash mode with SHA-512 (§6.2)
- Key validation with rho/tr consistency checks (§7.1)
- Constant-time verification via `subtle::ConstantTimeEq`
- Automatic zeroization of private key material on drop
- `no_std` and WASM compatibility
- Optional `serde` support behind `serde` feature flag
- NIST KAT vector validation for all 3 parameter sets
- Binary serialization with mode tagging
- 65 tests (25 unit, 17 coverage, 4 KAT, 17 round-trip, 2 doc-tests)
- Zero `unsafe` blocks

[0.2.0]: https://github.com/lattice-safe/dilithium-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lattice-safe/dilithium-rs/releases/tag/v0.1.0
