# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/lattice-safe/dilithium-rs/releases/tag/v0.1.0
