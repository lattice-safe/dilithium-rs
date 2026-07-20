# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-20

### Security
- **F1**: Fixed `simd` feature failing to compile on x86_64 (undefined `QINV32`,
  missing `ZETAS` import in `ntt_avx2.rs`)
- **F2**: SIMD NTT is now actually wired into `Poly::ntt`/`Poly::invntt_tomont`
  (previously dead code — the `simd` feature had no runtime effect);
  `no_std` + `simd` now uses compile-time feature detection on x86_64
- **F3**: All secret intermediates are now zeroized: `key`, `s1`, `s2`, `t0`,
  `t` in keygen; `s1`, `s2`, `t0`, `rhoprime`, `y`, `y_ntt`, `w`, `w0` in
  signing. Added `Zeroize` impls for `Poly`, `PolyVecL`, `PolyVecK` and
  in-place `add_assign`/`sub_assign` ops to eliminate secret-bearing clones
- **F4**: `from_keys`/`from_bytes` now perform a full algebraic consistency
  check (`t = A·s1 + s2` recomputed and compared against pk `t1` and sk `t0`),
  rejecting tampered secret keys (fault-attack hardening)
- **F5**: Low-level `sign_signature*`, `verify_internal`, and `unpack_sig`
  now reject wrong-length inputs instead of panicking
- **F6**: Candidate challenge `c̃` is written to the signature buffer only
  after all rejection checks pass (no rejected-iteration state escapes)
- **F7**: Documented that `serde` serializes private keys in plaintext
- **F9**: Rejection-loop nonce uses `wrapping_add` (no debug-build panic path)
- **F10**: Fuzz targets now cover all three modes and wrong-length inputs
- **F11**: Migrated `deny.toml` to the cargo-deny v2 schema

### Changed
- `sign::sign_signature` / `sign::sign_hash` now return `-1` on bad key/buffer
  lengths; `sign_signature_internal` returns 0 instead of panicking

### Fixed
- **F12**: Silenced `unused_imports` warning for `Q` in `ntt_avx2.rs` on
  non-x86_64 targets — the import is now gated to the architectures/tests
  that reference it
- **F13**: Silenced `unused_must_use` warning in `benches/dilithium_bench.rs`
  by discarding the `verify` result explicitly. `--all-features --all-targets`
  now builds with **0 warnings**

### Tooling
- Added `Dockerfile` (minimal `rust:1-alpine` / musl image) that builds and
  runs the full test suite with `cargo test --all-features`
- Added `Dockerfile.coverage` (`rust:1-bookworm` / glibc image) that runs
  `cargo tarpaulin --features serde --fail-under 90`, mirroring CI
- Added `.dockerignore` to keep the build context small

### Testing
- New `tests/api_coverage.rs`: error `Display` variants, mode tag round-trips,
  `to_bytes`/`from_bytes`/`from_public_key` error paths, prehash round-trips
  for all modes, low-level ctx/length guards, all four malformed-hint
  encodings in `unpack_sig`, all-zero-signature rejection, tampered c̃/z/pk/ctx
  rejection, `add_assign`/`sub_assign` consistency, `chknorm` bound edge,
  `Zeroize` impls, and `Shake256State` incremental hashing
- New `tests/serde_coverage.rs`: serde round-trips for key pairs, signatures,
  modes, and errors (gated on `serde` feature)
- Coverage CI now runs with `--features serde` and enforces a **90% floor**
  via `cargo tarpaulin --fail-under 90` (currently **99.38%** line coverage)
- Added `test_key_validation_wrong_pubkey_size` (reaches the public-key size
  check in `from_keys`) and `test_lowlevel_sign_hash_short_sk_returns_error`
  (reaches the HashML-DSA short-secret-key error path) to `tests/round_trip.rs`
- New `scripts/algebra_check.py`: bit-exact algebraic verification of the
  arithmetic layer (25 checks: reduction contracts, exhaustive
  `power2round`/`decompose` over all of Z_Q, hint lemma, ZETAS table vs
  1753^brv8(k), NTT round-trip/convolution, AVX2/NEON Montgomery lane math,
  overflow bounds) — all passing

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

[0.3.0]: https://github.com/lattice-safe/dilithium-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lattice-safe/dilithium-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lattice-safe/dilithium-rs/releases/tag/v0.1.0
