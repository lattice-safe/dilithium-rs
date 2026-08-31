# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-31

Second audit round (algebraic, side-channel, memory-safety, coverage) — see
`SECURITY_AUDIT.md` § "Round 2". One specification violation and eight
hardening findings; 100% region/line/function coverage.

### Security
- **R2-1 (High)**: **HashML-DSA now embeds the correct OID.** FIPS 204
  Algorithm 4/5 put the *pre-hash function's* DER OID into `M'`
  (`2.16.840.1.101.3.4.2.3` for SHA-512, the same for all parameter sets).
  The crate embedded the per-mode `id-ml-dsa-*` signature-algorithm OIDs, with
  a malformed DER length byte. `sign_prehash`/`verify_prehash` were therefore
  self-consistent but not interoperable with any conforming implementation.
  Pure ML-DSA was unaffected
- **R2-2**: `Debug` on `DilithiumKeyPair` no longer prints the private key —
  the derived impl leaked it through `Zeroizing`'s pass-through `Debug`;
  it now renders `[REDACTED]`
- **R2-3**: The SHAKE output buffers that hold `s1`/`s2` (keygen) and the mask
  `y` (every signing iteration) are zeroized instead of being dropped intact
- **R2-4**: `serde` `Deserialize` now runs the full FIPS 204 §7.1 key
  validation (via `TryFrom` → `from_keys`) instead of bypassing every
  constructor check
- **R2-5**: `Poly::chknorm` and the polyvec wrappers scan every coefficient
  and every polynomial without early exit, so the position of the first
  out-of-bound coefficient in a rejected candidate no longer leaks (the C
  reference short-circuits here)
- **R2-6**: `rounding::make_hint` is branchless — the previous `||`/`&&`
  short-circuit distinguished `a0 > γ₂` from `a0 < −γ₂`, i.e. the sign of a
  secret `w0` coefficient. Output is bit-identical (KATs unchanged)
- **R2-7**: `polyvecl_pointwise_acc_montgomery` accumulates in place instead
  of cloning the secret partial sum on every one of the K·L products, and
  `polyeta_pack`/`polyt0_pack` zeroize their temporaries
- **R2-8**: `from_keys` compares the secret `t0` with a masked, constant-time
  comparison
- **R2-9**: `to_bytes()` returns `Zeroizing<Vec<u8>>` so the exported
  plaintext secret key is wiped on drop
- **R2-11**: `nonce + i` in the polyvec samplers uses `wrapping_add`,
  matching the already-hardened outer nonce

### Added
- `DilithiumKeyPair::generate_with_rng`, `sign_with_rng`,
  `sign_prehash_with_rng` — hedged key generation and signing from a
  caller-supplied entropy source (`&mut dyn FnMut(&mut [u8]) -> Result<(), ()>`).
  Available without the `std`/`getrandom` feature, so `no_std` targets can do
  hedged signing. A failing source yields `RandomError` and produces no key or
  signature
- `params::SHA512_OID` (the OID that goes into `M'`) and correct, separately
  named certificate identifiers: `ML_DSA_{44,65,87}_OID` (`id-ml-dsa-*`,
  sigAlgs 17–19) and `HASH_ML_DSA_{44,65,87}_OID`
  (`id-hash-ml-dsa-*-with-sha512`, sigAlgs 32–34), plus
  `DilithiumMode::{algorithm_oid, hash_algorithm_oid, prehash_oid}`
- `sign::pure_prefix` / `sign::prehash_prefix` — the `M'` constructions as
  single shared functions instead of four duplicated call sites
- In-place kernels `Poly::{pointwise_montgomery_assign, use_hint_assign}` and
  `polyveck_{pointwise_poly_montgomery_assign, use_hint_assign}`;
  verification no longer clones three whole polynomial vectors
- `symmetric::XofStream` — lets the rejection-sampling refill paths be driven
  by a test stream
- `tests/acvp_kat.rs` (5 tests) with `tests/data/acvp_ml_dsa.json`: **official
  NIST ACVP vectors** — 75 `keyGen`, 12 pure `sigGen` (deterministic, context
  0–245 bytes), SHA-512 HashML-DSA `sigGen` (deterministic byte-for-byte) and
  verification of NIST's hedged pre-hash signatures, and 19 `sigVer` cases
  including all four of NIST's negative classes (modified message,
  commitment, hint, `z`). This is the external confirmation that R2-1 is
  fixed: with the pre-0.4.0 OID the deterministic pre-hash test fails
- `tests/hash_ml_dsa_conformance.rs` (6 tests): `M'` bytes pinned against an
  independent transcription of FIPS 204 Algorithm 4/5, plus pure/pre-hash
  domain separation
- `tests/rejection_paths.rs` (3 tests): reaches the `‖c·t0‖∞ ≥ γ₂` rejection
  branch (p ≈ 2⁻²³ per iteration with real keys) and asserts the signing loop
  still terminates
- `fuzz_verify` fuzz target: adversarial signature bytes and single-bit
  mutations of genuine signatures against a real public key, all three modes,
  both domains
- Compile-time assertion that the L-fold Montgomery accumulator stays inside
  `reduce32`'s input bound

### Changed
- Benchmarks re-measured on an idle machine with a matched C harness, and the
  signing benchmark now **varies the message per iteration**. With a fixed
  `(sk, msg, rnd)` the rejection loop is deterministic, so the old figures
  reported one arbitrary rejection count — which is why ML-DSA-65 signing
  previously appeared 1.5× slower than the C reference. Verification also got
  faster in this release (three whole `PolyVecK` clones removed)
- **CI now executes the SIMD kernels** (`cargo test --release --features simd`
  and `--all-features`). The AVX2/NEON NTT is the crate's only `unsafe` code
  and was previously compiled but never run by any test job (R2-10)
- Coverage gate moved from `cargo tarpaulin --fail-under 90` to
  `cargo llvm-cov --all-features` at **100%** regions, lines and functions
  (`Dockerfile.coverage` updated to match)
- The `|ctx| ≤ 255` limit is enforced in one place (`sign::sign_signature` /
  `sign::sign_hash`) rather than duplicated in the safe wrappers; the
  resulting error is unchanged (`DilithiumError::BadArgument`)
- `DilithiumMode::hash_oid()` removed — it returned the wrong value for its
  only use. Use `prehash_oid()` for the `M'` OID, or `algorithm_oid()` /
  `hash_algorithm_oid()` for certificate identifiers

### Breaking
- HashML-DSA signature format changed (R2-1). `sign_prehash` output from
  v0.3.0 and earlier will not verify. Pure ML-DSA signatures, public keys and
  secret keys are unchanged
- `to_bytes()` returns `Zeroizing<Vec<u8>>` instead of `Vec<u8>` (derefs to
  `Vec<u8>`/`[u8]`, so most call sites are unaffected)
- `serde` `Deserialize` for `DilithiumKeyPair` now rejects invalid key pairs
  instead of accepting them
- `DilithiumMode::hash_oid()` renamed/replaced (see Changed)

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
- **MSRV raised to 1.85** (from 1.70): current dependencies (e.g. `zeroize`
  1.9) require the 2024 edition. CI's MSRV job now pins `1.85`
- `sign::sign_signature` / `sign::sign_hash` now return `-1` on bad key/buffer
  lengths; `sign_signature_internal` returns 0 instead of panicking

### Fixed
- **F12**: Gated the SIMD-only params imports so cross-arch builds are
  warning-free: `Q` in `ntt_avx2.rs` (unused on non-x86_64) and
  `ZETAS`/`Q`/`QINV` in `ntt_neon.rs` (unused on non-aarch64, e.g. the x86_64
  CI runner) are now scoped to the architectures/tests that reference them
- **F13**: Silenced `unused_must_use` in `benches/dilithium_bench.rs` and
  removed needless `return`s in `poly.rs`, so
  `cargo clippy --all-features --all-targets -- -D warnings` passes on both
  x86_64 and aarch64
- **F14**: Applied `cargo fmt` across the tree so `cargo fmt --check` passes
- **F15**: Dependency-audit CI now runs `cargo deny` on the runner's stable
  toolchain (the pinned container action shipped a Cargo too old to parse
  edition-2024 dependencies). Fresh resolution now pulls patched
  `crossbeam-epoch` (≥ 0.9.20, RUSTSEC-2026-0204) and `rand` (≥ 0.8.7,
  RUSTSEC-2026-0097) — both dev-only, so the shipped crate was never affected

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
