# Security Audit — dilithium-rs

This file accumulates the audit rounds performed on this crate. The most
recent round is first.

- [Round 2 — v0.4.0 (2026-08-31)](#round-2--v040-2026-08-31): algebraic,
  side-channel, memory-safety and coverage audit. One HIGH finding
  (HashML-DSA OID) plus seven hardening fixes.
- [Round 1 — v0.2.0 (2026-07-20)](#round-1--v020-2026-07-20): initial audit,
  eleven findings, all fixed in v0.3.0.

---

# Round 2 — v0.4.0 (2026-08-31)

**Scope:** Full source review of `src/` plus tests, fuzz targets, CI and
supply-chain config, along four independent axes: (1) algebraic correctness
against FIPS 204 and the CRYSTALS-Dilithium C reference, (2) constant-time /
side-channel behaviour, (3) memory safety, `unsafe` soundness and public-API
robustness against adversarial input, (4) test-coverage completeness.

**Method:** Manual review plus *computational* verification — constants and
tables recomputed from first principles, the rounding functions checked
**exhaustively over all 8,380,417 field elements**, the NTT checked against
schoolbook negacyclic convolution, the SIMD lane algebra modelled bit-exactly,
and the whole feature/target matrix built and adversarially exercised. All
dynamic checks in this round were actually executed (unlike Round 1).

## Summary

The core ML-DSA arithmetic is a faithful, correct port: every constant, twiddle
table entry, rounding function, sampler, norm check and packing rule was
verified independently, and the 100-vector-per-mode KAT suite matches the C
reference bit-for-bit (also with the `simd` feature enabled, which validates
the NEON kernels end to end).

**One specification violation was found and fixed:** HashML-DSA embedded the
wrong object identifier in the pre-hash message representative `M'` — the
per-parameter-set signature-algorithm OID instead of the pre-hash function's
OID — and the bytes were not even well-formed DER. Pure ML-DSA was unaffected.

The remaining findings are hardening: secret residue left in un-zeroized
sampling buffers, two reference-inherited short-circuits over secret values,
a `Debug` impl that printed the private key, and a `serde` path that bypassed
key validation.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| R2-1 | **High** (spec / interop) | HashML-DSA `M'` embeds the wrong OID (`id-ml-dsa-*` instead of the SHA-512 OID), with a malformed DER length byte | ✅ Fixed |
| R2-2 | Medium | `Debug` on `DilithiumKeyPair` printed the plaintext private key | ✅ Fixed |
| R2-3 | Medium | Secret SHAKE output buffers (`s1`/`s2` in keygen, the mask `y` on every signing iteration) were dropped without zeroization | ✅ Fixed |
| R2-4 | Medium | `serde` `Deserialize` bypassed all constructor validation | ✅ Fixed |
| R2-5 | Low | `chknorm` early-returned on the first out-of-bound coefficient (leaks its position for rejected candidates) | ✅ Fixed (branchless) |
| R2-6 | Low | `make_hint` short-circuited over the secret `w0` (leaks the sign of a secret coefficient) | ✅ Fixed (branchless) |
| R2-7 | Low | Secret partial sums copied by `w.clone()` in the pointwise accumulator, and pack temporaries left un-zeroized | ✅ Fixed |
| R2-8 | Low | `from_keys` compared the secret `t0` with a variable-time `!=` | ✅ Fixed (masked) |
| R2-9 | Low | `to_bytes()` returned the plaintext secret key in a non-zeroizing `Vec` | ✅ Fixed |
| R2-10 | Medium (assurance) | CI never *executed* the `simd` kernels — the crate's only `unsafe` code had zero executed test coverage | ✅ Fixed |
| R2-11 | Info | `nonce + i` in the polyvec samplers was non-wrapping (debug-build panic path, unreachable in practice) | ✅ Fixed |

Verified as **not** vulnerable (see "Checked and found correct"): no memory
unsafety, no reachable panic on attacker-controlled bytes across 34
adversarial cases and the whole feature matrix, no secret-indexed table
lookup, no unsound `unsafe`.

## Findings

### R2-1 — HashML-DSA embeds the wrong OID (High)

`src/params.rs`, consumed by `sign_hash` / `verify_hash`.

FIPS 204 §5.4 (Algorithms 4 and 5, line 21) builds the pre-hash message
representative as

```text
M' = IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M
```

where `OID` is the DER encoding of the **pre-hash function's** object
identifier. For SHA-512 that is `2.16.840.1.101.3.4.2.3`, encoded as the
11 bytes `06 09 60 86 48 01 65 03 04 02 03`, and it is the same for
ML-DSA-44/65/87 — its purpose is to tell the verifier *which pre-hash* was
applied. (Confirmed against the FIPS 204 text and against Bouncy Castle's
`HashMLDSASigner`, which derives the value from
`DigestUtils.getDigestOid(digest.getAlgorithmName())`.)

The crate instead embedded per-mode constants
`06 0B 60 86 48 01 65 03 04 03 11/12/13`. Three separate errors:

1. **Wrong OID family.** The value bytes decode to `2.16.840.1.101.3.4.3.17/18/19`
   = `id-ml-dsa-44/65/87` — the *signature algorithm* identifiers used in
   certificates, not a hash OID.
2. **Malformed DER.** The length byte says `0x0B` (11) but only 9 content
   bytes follow.
3. **Wrong doc comment.** They were labelled
   `id-HashML-DSA-*-with-SHA512`, which is yet a third thing
   (`2.16.840.1.101.3.4.3.32/33/34`).

**Impact.** `sign_prehash` / `verify_prehash` were self-consistent, so
round-trip tests passed — but the signatures were **not FIPS 204 HashML-DSA
signatures**: no conforming implementation could verify them, and conforming
signatures failed here. Pure ML-DSA (`sign`/`verify`) was unaffected, which
the KAT suite already proved.

**Fix.** `params::SHA512_OID` holds the correct 11-byte DER encoding and is
what goes into `M'`. The certificate identifiers are now exposed separately
and correctly — `algorithm_oid()` (`id-ml-dsa-*`, sigAlgs 17–19) and
`hash_algorithm_oid()` (`id-hash-ml-dsa-*-with-sha512`, sigAlgs 32–34) — with
doc comments stating that neither participates in the signature computation.
The `M'` construction is now a single shared function per domain
(`sign::pure_prefix`, `sign::prehash_prefix`) instead of being duplicated
across four call sites, and `tests/hash_ml_dsa_conformance.rs` pins its bytes
against an independent literal transcription of Algorithm 4.

**External validation.** The fix is confirmed against the **official NIST
ACVP vectors** (`ML-DSA-sigGen-FIPS204`, external interface, `preHash`,
SHA2-512): the deterministic vectors now reproduce byte-for-byte for all
three parameter sets, and NIST's hedged pre-hash signatures verify. A
negative control was run — restoring the pre-0.4.0 OID makes
`acvp_siggen_prehash_sha512_deterministic` fail — so the test is not
vacuous. See `tests/acvp_kat.rs`.

**Compatibility.** This changes the HashML-DSA wire format. Signatures
produced by v0.3.0 and earlier with `sign_prehash` no longer verify — they
were never interoperable. Pure ML-DSA signatures and all key encodings are
unchanged.

### R2-2 — `Debug` printed the private key (Medium)

`DilithiumKeyPair` derived `Debug`, and `Zeroizing<Vec<u8>>` forwards `Debug`
to its inner `Vec`, so any `{:?}` of a key pair — a log line, a panic
message, a `#[derive(Debug)]` on an enclosing struct — dumped the full
plaintext private key. Replaced with a manual impl that prints the mode and
the key lengths and renders the private key as `[REDACTED]`.

### R2-3 — Secret sampling buffers not zeroized (Medium)

`Poly::uniform_eta` and `Poly::uniform_gamma1` allocated a `Vec<u8>` (plus a
stack block per refill), squeezed SHAKE256 into it, and dropped it. Those
bytes *are* the secret material: the packed coefficients of `s1`/`s2` during
key generation and of the mask `y` on **every** signing iteration (4–7
buffers per iteration). They were left in freed heap memory, contradicting
the crate's zeroization guarantee. All such buffers are now zeroized before
going out of scope.

Residual, documented: the `sha3` XOF reader state itself (a Keccak state
derived from `rho'`) is not zeroizable through the `sha3` API.

### R2-4 — `serde` `Deserialize` bypassed validation (Medium)

The derived `Deserialize` populated the struct fields directly, so a key pair
from an untrusted blob skipped every check that `from_bytes`/`from_keys`
perform — its `mode` could disagree with its key lengths and its secret key
need not satisfy `t = A·s1 + s2`. No panic or misverification resulted (that
was confirmed by adversarial testing), but callers trusting
`kp.private_key()` got unvalidated bytes, and a tampered secret key is
exactly the input the Round-1 fault-attack hardening (F4) was meant to
reject. `Deserialize` now goes through a private wire struct and
`TryFrom` → `from_keys`, so deserialization enforces the same FIPS 204 §7.1
invariants as every other constructor.

### R2-5 / R2-6 — Reference-inherited short-circuits over secret values (Low)

Both follow the C reference, which short-circuits too; both are now
branchless, which is strictly stronger and bit-identical in output (the KAT
suite still matches).

- **`Poly::chknorm`** returned on the first coefficient exceeding the bound,
  so the running time revealed the *position* of the first large coefficient
  in a rejected `z = y + c·s1`, `w0 − c·s2` or `c·t0`. The accept path always
  scanned everything, so only rejected (never-published) candidates leaked,
  and the reference documents this as acceptable — but there is no reason to
  keep it: the scan is now unconditional and accumulates a mask.
  `polyvecl_chknorm` / `polyveck_chknorm` likewise no longer exit early on
  the first offending polynomial.
- **`rounding::make_hint`** was written as
  `a0 > γ₂ || a0 < −γ₂ || (a0 == −γ₂ && a1 != 0)`. The hint *bit* is public
  (it is in the signature), but the `||` short-circuit additionally
  distinguishes `a0 > γ₂` from `a0 < −γ₂` — the sign of a secret `w0`
  coefficient. Now computed with sign-bit masks; the truth table is pinned by
  a test that compares it against the reference expression across the whole
  reachable `a0` range for all three modes.

### R2-7 — Secret residue in accumulator and pack temporaries (Low)

`polyvecl_pointwise_acc_montgomery` did `let w_copy = w.clone(); Poly::add(w,
&w_copy, &t)` inside the accumulation loop — a 1 KiB copy of a secret partial
sum (`A·NTT(y)` during signing), left un-zeroized, for each of the K·L
products. Replaced with in-place `add_assign` (also removing K·L copies of
work per signature and per verification), and the `t` accumulator is
zeroized. `polyeta_pack` and `polyt0_pack` now zeroize their 8-element
temporaries, which hold `η − s` and `2^{D−1} − t0`.

Verification was cloning three whole `PolyVecK`s for the same reason; it now
uses in-place kernels (`polyveck_pointwise_poly_montgomery_assign`,
`polyveck_use_hint_assign`, `polyveck_sub_assign`), whose equivalence with
the out-of-place forms is tested.

### R2-8 — Variable-time comparison of the secret `t0` (Low)

`from_keys` compared `t0.vec[i].coeffs != t0_expected.vec[i].coeffs`. The loop
correctly avoided an early `break`, but array `!=` is itself variable-time and
reveals the first differing coefficient. Now an XOR-accumulated masked
comparison. (Severity is low because the caller supplies both operands; this
is not a signing or verification oracle.)

### R2-9 — `to_bytes()` handed out unprotected secret bytes (Low)

`to_bytes()` returned a plain `Vec<u8>` containing the plaintext secret key.
It now returns `Zeroizing<Vec<u8>>`, which derefs to `Vec<u8>`/`[u8]` so
existing call sites keep working, and the buffer is wiped on drop.

### R2-10 — CI never executed the SIMD kernels (Medium, assurance)

The AVX2 and NEON NTT kernels are the only `unsafe` code in the crate, and
they live behind `#[cfg(feature = "simd")]`. CI ran `cargo test --release`
and `cargo test --release --features serde` only; `--all-features` appeared
solely in `cargo check`/`clippy`, which compile but never *run* the
SIMD-vs-scalar equivalence tests. The hand-written Montgomery lane algebra
therefore had zero executed coverage on either runner. CI now also runs
`cargo test --release --features simd` and `--all-features`, so the AVX2
kernels are exercised on the x86_64 runner and NEON on the macOS arm64 one —
including the full 100-vector KAT suite through the SIMD path.

### R2-11 — Non-wrapping nonce arithmetic (Info)

`nonce + i as u16` in `polyvecl_uniform_eta` / `polyvecl_uniform_gamma1` /
`polyveck_uniform_eta` would panic in a debug build if the outer nonce
approached `u16::MAX` (~9,300 consecutive rejections; unreachable in
practice, and the outer nonce was already `wrapping_add`). Made consistent
with `wrapping_add`.

## Checked and found correct (computationally verified)

- **Montgomery arithmetic.** `Q·QINV ≡ 1 (mod 2³²)` confirmed; over 2M random
  inputs spanning the full documented precondition range, `montgomery_reduce`
  returns `r ≡ a·2⁻³² (mod Q)` with `|r| < Q`, and the wrapping `i32` multiply
  exactly reproduces the C `(int32_t)a * QINV` semantics.
- **ZETAS table.** All 255 used entries independently recomputed as centred
  representatives of `1753^brv₈(k)·2³² mod Q` — zero mismatches. `ZETAS[0]`
  is a never-indexed placeholder, as in the reference. `f = 41978 ≡ mont²/256
  (mod Q)` confirmed.
- **NTT.** `invntt(ntt(x)) = x·2³² mod Q`; `invntt(ntt(a) ∘ ntt(b))` equals a
  schoolbook negacyclic product in `Z_Q[X]/(X²⁵⁶+1)` exactly.
- **Coefficient growth.** No overflow anywhere: forward NTT ≤ ~9Q; inverse NTT
  worst accumulation ≈1.6·10⁹ < 2³¹; the L-fold Montgomery accumulator stays
  under `7Q ≈ 5.9·10⁷`, far inside `reduce32`'s `2³¹ − 2²² − 1` precondition
  (now asserted at compile time in `polyvec.rs`); pointwise products ≈5.1·10¹⁵
  < the `Q·2³¹` Montgomery precondition.
- **Rounding.** `power2round` and `decompose` verified **exhaustively over all
  8,380,417 field elements** for both γ₂ values, including the `γ₂=(Q−1)/88`
  `a1 = 43 → 0` wrap and the `r⁺ − r0 = q−1` edge. `use_hint` verified against
  Algorithm 40 at ~350K points including every multiple of 2γ₂ ±3, and the
  scheme identity `UseHint(MakeHint(w0−e, w1), w−e) = w1` at 700K+ points.
- **Samplers.** `rej_uniform` implements `CoeffFromThreeBytes` (23-bit mask,
  `< Q`); both buffer sizes (840 initial, 168 per refill) are multiples of 3,
  so dropping the reference's leftover-carry bookkeeping is exactly
  equivalent. `rej_eta` matches `CoeffFromHalfByte` for both η. SampleInBall
  absorbs the full `c̃` and uses Fisher–Yates with the 8 leading sign bytes.
- **Domain separation.** ExpandA nonce `(i≪8)+j` little-endian; ExpandS nonces
  `0..ℓ` and `ℓ..ℓ+k`; ExpandMask `κ·ℓ + i`; KeyGen `H(ξ‖k‖ℓ)` split 32/64/32;
  `μ = H(tr‖M')`; `ρ'' = H(K‖rnd‖μ)`.
- **Rejection bounds.** `‖z‖∞ ≥ γ₁−β`, `‖r0‖∞ ≥ γ₂−β`, `‖c·t0‖∞ ≥ γ₂`,
  `popcount(h) > ω` — all with the FIPS-correct comparison operators; `c̃` is
  written to the caller's buffer only after every check passes.
- **Verification and malleability.** Exact signature length; `z` norm
  re-checked before use; `w1' = UseHint(h, Az − c·2^d·t1)`; constant-time
  `c̃` comparison; hint decoding enforces monotonically increasing indices,
  cumulative counts ≤ ω and zero padding (FIPS 204 Algorithm 21).
- **`unsafe` soundness.** Every `target_feature(enable = "avx2")` function is
  reached only behind `is_x86_feature_detected!` (std) or
  `cfg(target_feature = "avx2")` (no_std); NEON needs no gate on aarch64.
  Loads/stores are the unaligned intrinsics (correct for a 4-byte-aligned
  `[i32; 256]`); the loop invariants keep both the `[j..]` and `[j+len..]`
  windows in bounds, and they are disjoint whenever the SIMD branch runs.
- **Panic-freedom.** 34 adversarial cases through the public API — empty,
  truncated, oversized and boundary-length inputs to `from_bytes`,
  `from_public_key`, `from_keys`, `verify`, `verify_prehash`, cross-mode
  signatures, `ctx` at 255/256/300 bytes, serde blobs with inconsistent
  lengths — produced no panic. The three `unwrap()`s in library code are
  infallible `try_into`s on fixed-size buffers.
- **Feature/target matrix.** `--no-default-features`, `+serde`, `+simd`,
  `+js`, `--all-features`, and the `thumbv7em-none-eabihf` /
  `wasm32-unknown-unknown` targets all build clean, including no_std + simd
  (confirming `is_x86_feature_detected!` does not leak into no_std).
- **No secret-indexed lookups.** Every varying index is public: `ZETAS[k]`
  (fixed schedule), the SampleInBall shuffle index (from the public `c̃`),
  hint indices (public / attacker-supplied), and sequential writes in
  rejection sampling.
- **Dependencies.** `sha3` 0.10.8, `sha2` 0.10.9, `zeroize` 1.8.2, `subtle`
  2.6.1, `getrandom` 0.2.17, `serde` 1.0.228 — current, no open advisories,
  no build scripts, no C bindings; `deny.toml` is schema-v2 correct.

### Correction to Round 1

Round 1's "found correct" list stated that the HashML-DSA prefix used
"correct per-mode OIDs". That was wrong on both counts — see R2-1. The
per-mode OIDs it referred to were also malformed DER. Round 1 verified the
prefix *structure* but never checked the OID bytes against the specification,
and no test pinned them; the round-trip tests passed because signing and
verification shared the same mistake. `tests/hash_ml_dsa_conformance.rs` now
closes that gap.

## External conformance vectors added

Beyond the fixes, this round added the official NIST ACVP vectors to the test
suite (`tests/acvp_kat.rs`, data in `tests/data/acvp_ml_dsa.json`):

| Vector set | What it proves |
|---|---|
| `ML-DSA-keyGen-FIPS204`, 75 vectors (all 3 modes × 25) | `ξ → (pk, sk)` matches NIST exactly |
| `ML-DSA-sigGen-FIPS204`, pure external deterministic, 12 vectors | Signatures match byte-for-byte with real context strings (0–245 bytes) |
| `ML-DSA-sigGen-FIPS204`, `preHash` SHA2-512, 3 deterministic + 4 hedged | The pre-hash `M'` — OID included — is interoperable, not merely self-consistent |
| `ML-DSA-sigVer-FIPS204`, external, 19 vectors | Valid signatures accepted; NIST's four negative classes (modified message, commitment `c̃`, hint, `z`) all rejected |

Previously the only cross-implementation evidence was the pq-crystals
C-reference KAT, which covers the pure path only — which is precisely why
R2-1 went unnoticed for two releases.

## Coverage

Test coverage was raised from 99.47% of regions to **100% of regions, lines
and functions** (`cargo llvm-cov --all-features`), enforced in CI. The gap
mattered: the uncovered regions were precisely the security-relevant rare
paths.

| Previously uncovered | Now covered by |
|---|---|
| The `‖c·t0‖∞ ≥ γ₂` rejection branch (p ≈ 2⁻²³ per iteration with real keys) | `tests/rejection_paths.rs` — a secret key with enlarged `t0`, chosen so the bound is exceeded a few percent of the time while the hint weight stays under ω, so the loop still terminates |
| The rejection-sampling refill loop in `RejNTTPoly` (unreachable with a real XOF, p < 2⁻¹⁰⁰) | An injectable `XofStream` whose first block is all `0xFF`, so every candidate is rejected; the result is compared against an independent re-derivation |
| The `a0 == −γ₂` clause of `make_hint` | An exhaustive truth-table comparison against the reference expression |
| RNG-failure paths | The new bring-your-own-RNG API with a failing entropy source, asserting no key or signature is produced |
| Malformed-serde and corrupt-key-state guards | `tests/serde_coverage.rs` and unit tests constructing an inconsistent key pair |
| SIMD kernels (compiled but never run in CI) | `cargo test --features simd` in CI on both runners |

Two API changes came out of this: the `|ctx| ≤ 255` check is no longer
duplicated between the safe wrappers and `sign::*` (it lives in one place, and
the wrapper's error path is now reachable and tested), and the entropy hook is
public, which both makes the failure path testable and gives `no_std` targets
a way to use hedged signing without `getrandom`.

## Reproducing this round

```sh
cargo test --all-features                   # 142 tests
cargo test --release --features simd        # AVX2 / NEON kernels + KATs
cargo llvm-cov --all-features \
  --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions 100
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
python3 scripts/algebra_check.py src/ntt.rs # bit-exact arithmetic model
cargo +nightly fuzz run fuzz_verify -- -max_total_time=300
cargo build --no-default-features --target thumbv7em-none-eabihf
cargo build --no-default-features --features js --target wasm32-unknown-unknown
```

## Residual risk

- **Not a certified module.** No CMVP validation. (Interoperability itself
  is now covered: official NIST ACVP keyGen/sigGen/sigVer vectors are in the
  test suite, including SHA-512 HashML-DSA.)
- **Pre-hash support is SHA-512 only.** FIPS 204 also approves SHA-256,
  SHA3-224/256/384/512 and SHAKE-128/256 as pre-hash functions; ACVP vectors
  for those are skipped rather than failed.
- **Source-level constant-time only.** The branchless forms were reviewed at
  source level; LLVM is free to reintroduce branches. A `dudect`-style or
  valgrind/ctgrind measurement on release binaries is the next step.
- **XOF state not zeroizable.** The `sha3` reader state derived from `rho'`
  outlives sampling (see R2-3).
- **AVX2 kernels not executed in this session** (aarch64 host); they are now
  exercised by CI on x86_64, and their lane algebra was verified with a
  bit-exact model.
- **No formal verification.**

---

# Round 1 — v0.2.0 (2026-07-20)

**Date:** 2026-07-20
**Scope:** Full source review of `src/` (3,449 LoC), tests, fuzz targets, CI, and supply-chain config. Cross-checked against the CRYSTALS-Dilithium C reference implementation and FIPS 204 (final).
**Method:** Manual line-by-line review. Dynamic verification (cargo test/clippy/deny) was not run in this session — see "Recommended verification" below.

---

## Summary

The core (default-feature) implementation is a faithful, careful port of the C reference and is in good shape: parameters match FIPS 204 final (64-byte `tr`, hedged signing with `rnd`, keygen domain separation `H(ξ‖k‖l)`, ctx-prefixed messages, correct HashML-DSA OIDs), signature hint decoding fully enforces the strong-unforgeability encoding rules, the safe API validates all input lengths, and challenge comparison in verify is constant-time. KAT tests validate against C reference vectors across all three modes.

The significant problems are concentrated in the **`simd` feature (broken/dead code)**, **incomplete zeroization of secret intermediates**, and **incomplete §7.1 key validation in `from_keys`**. No practically exploitable forgery or key-recovery path was identified in the default configuration.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F1 | High (build) | `simd` feature does not compile on x86_64 — undefined `QINV32`, unimported `ZETAS` | ✅ Fixed |
| F2 | Medium | SIMD NTT is dead code — never wired into `Poly::ntt`, so `simd` provides no acceleration | ✅ Fixed |
| F3 | Medium | Incomplete zeroization of secret intermediates in `keypair` and `sign_signature_internal` | ✅ Fixed |
| F4 | Medium | `from_keys` accepts secret keys whose `s1/s2/t0` are inconsistent with the public key | ✅ Fixed |
| F5 | Low | Low-level public modules panic on wrong-length inputs | ✅ Fixed |
| F6 | Low | Rejected-iteration challenge bytes written to caller's signature buffer | ✅ Fixed |
| F7 | Low | `serde` serializes private keys in plaintext without warning | ✅ Documented |
| F8 | Info | SECURITY.md version table stale (0.1.x vs crate 0.2.0) | ✅ Fixed |
| F9 | Info | Theoretical `u16` nonce overflow in rejection loop | ✅ Fixed |
| F10 | Info | Fuzzing covers only ML-DSA-44 | ✅ Fixed |
| F11 | Info | `deny.toml` uses deprecated cargo-deny schema keys | ✅ Fixed |

> **Remediation (2026-07-20):** all findings addressed in the same session —
> see the `[Unreleased]` section of `CHANGELOG.md` for details, and the
> regression tests added to `tests/round_trip.rs` (tampered-`s1`/`t0`
> rejection, short-input non-panic). The fixes were applied by static
> review; run the verification commands below before release.

---

## Findings

### F1 — `simd` feature fails to compile on x86_64 (High, build-breaking)

`src/ntt_avx2.rs:44` uses `QINV32`, which is **never defined anywhere in the crate** (the comment block at line 28 suggests the const was deleted or never written). Additionally, `ZETAS` is used at lines 132/166 with no `use crate::ntt::ZETAS;` import. Both are inside `#[cfg(target_arch = "x86_64")]` items, so:

- `cargo check --features simd` fails on any x86_64 target.
- CI's `cargo check --all-features` (MSRV job) and `cargo clippy --all-features` on `ubuntu-latest` will fail. If CI is green, these jobs are not actually exercising what they claim.
- On aarch64 the module happens to compile because the broken items are cfg'd out.

**Fix:** add `const QINV32: i32 = 58728449u32 as i32;` (Q·QINV ≡ 1 mod 2³²; note `params::QINV` is `i64`) and `use crate::ntt::ZETAS;`, then gate a CI job on an actual x86_64 runner with `--features simd` and run the `test_ntt_simd_matches_scalar` tests there.

### F2 — SIMD NTT is dead code (Medium, correctness-of-claims)

`ntt_simd`/`invntt_simd` (both AVX2 and NEON variants) are defined but **nothing calls them**: `Poly::ntt`/`Poly::invntt_tomont` unconditionally call the scalar `ntt::ntt`/`ntt::invntt_tomont`. Enabling `simd` compiles extra `unsafe` code but changes nothing at runtime. README/CHANGELOG/docs claims of "SIMD acceleration" are therefore not true, and the NEON path — while internally tested against scalar — is never exercised by KATs through the real signing path.

**Fix:** dispatch in `Poly::ntt` under `#[cfg(feature = "simd")]` (e.g. arch-conditional call to `ntt_neon::ntt_simd` / `ntt_avx2::ntt_simd`), or remove the feature until it's integrated. Note `is_x86_feature_detected!` is std-only — guard the x86 dispatch for `no_std` + `simd` combinations.

### F3 — Incomplete zeroization of secret intermediates (Medium)

The docs claim "private key material is automatically zeroized". This holds for the packed `sk` (`Zeroizing<Vec<u8>>`) and a few buffers (`seedbuf`, `expanded`, `rhoprime` in keygen; `key` in sign; `rnd`/`seed` in the safe API), but not for:

- **`keypair`** (`src/sign.rs`): the local `key` array (the long-term signing seed!), `s1`, `s2`, `s1hat`, `t0`, and pre-rounding `t1` are dropped without zeroization.
- **`sign_signature_internal`**: unpacked `s1`, `s2`, `t0` (and their NTT forms), `rhoprime` (deterministic-mode secret), the mask vector `y`, `z_ntt`, `w0`, and the challenge product intermediates in `h` all remain in stack/heap memory after return.

These are classic cold-boot/memory-disclosure hardening gaps rather than remote vulnerabilities, but for a crate whose selling point is zeroization the coverage should match the claim.

**Fix:** implement `Zeroize` for `Poly`/`PolyVecL`/`PolyVecK` and zeroize all secret-derived locals on every exit path (including rejection-loop `continue`s for `y`); or scope the claim in the docs.

### F4 — `from_keys` key validation is incomplete (Medium)

`DilithiumKeyPair::from_keys` (FIPS 204 §7.1) checks lengths, `rho` equality, and `tr == H(pk)` — but `s1`, `s2`, `t0` occupy the bulk of `sk` and are **not validated against `pk`** (no check that `t = A·s1 + s2` is consistent with the packed `t1`). An attacker who can tamper with stored secret keys (while preserving the first 128 bytes) gets the library to sign with a corrupted key. Signing with faulted/inconsistent Dilithium keys is a known key-recovery vector (fault-attack literature; the differential between expected and actual `w` leaks information about `s1`).

**Fix:** on import, unpack `sk`, recompute `t = A·s1 + s2`, apply `power2round`, and compare the high part against the `t1` in `pk` (and optionally `t0` against the low part). This is cheap relative to one signing operation. At minimum, document that `from_keys`/`from_bytes` must only be fed integrity-protected key material.

### F5 — Low-level public API panics on malformed input lengths (Low)

`sign`, `packing`, `poly`, `polyvec` are `pub` (merely `#[doc(hidden)]`), and the fuzz targets themselves use them. These functions index slices without length checks:

- `sign::verify_internal` / `sign::verify` with a short `pk` → panic in `unpack_pk`.
- `sign::sign_signature*` with a short `sk` → panic in `unpack_sk`.
- `packing::unpack_sig` assumes `sig.len() == signature_bytes()` (callers check today, but the function itself will panic on short input).

The safe API (`safe_api.rs`) validates lengths correctly, so this is an API-misuse/DoS hazard for downstream users who reach past it.

**Fix:** either make these modules `pub(crate)` (breaking change; the fuzz targets can use a feature-gated export), or add explicit length checks returning errors at each low-level entry point.

### F6 — Candidate challenge written to output buffer before rejection checks (Low)

`sign_signature_internal` copies each candidate `c̃` into the caller's `sig` buffer (`src/sign.rs:158`) before the norm checks; rejected iterations' values are only overwritten by `pack_sig` on success. If a caller ever inspects the buffer after a panic/abort mid-loop, it holds internal state from a rejected iteration. Cosmetic in the current call graph, but the copy belongs after the checks (only `ctilde_buf` needs to survive the iteration — it's already passed to `pack_sig`).

### F7 — `serde` feature serializes plaintext private keys (Low)

`DilithiumKeyPair`'s `Serialize` emits the raw private key. Anyone deriving a log/debug/JSON path over a keypair exfiltrates the key. `Debug` is safe-ish today only because `Zeroizing`'s debug hides content — verify this and document loudly that serialized keypairs must be treated as secrets (or serialize only the public half by default and require an explicit opt-in type for full export).

### F8 — SECURITY.md drift (Info)

Supported-versions table says `0.1.x` while the crate is `0.2.0`. Update on each release.

### F9 — Theoretical nonce overflow (Info)

The rejection loop's `nonce: u16` increments by `l` per iteration; after ~9,300+ rejections (probability astronomically small, ~(3/4)^9300) it overflows — a panic in debug builds. Matches the C reference's behavior; acceptable, but `wrapping_add` plus a comment would make intent explicit.

### F10 — Fuzz coverage limited to ML-DSA-44 (Info)

`fuzz_sign_verify` and `fuzz_unpack_sig` hardcode `Dilithium2`. ML-DSA-65 is the only mode with `eta = 4` and ML-DSA-87 has distinct `k/l/omega/ctilde` — parameter-dependent packing paths are unfuzzed. Derive the mode from the first input byte. Also consider a fuzz target for `verify` with arbitrary sig+pk bytes through the low-level API once F5 is fixed.

### F11 — deny.toml uses deprecated schema (Info)

`vulnerability`, `unlicensed`, `copyleft`, and `notice` keys were removed in cargo-deny's v2 schema (≥ 0.14.3); modern cargo-deny errors on them, which would silently break the CI advisory gate. Migrate to the current `[advisories]`/`[licenses]` format.

---

## What was checked and found correct

- **Parameters** (`params.rs`): all constants (k, l, η, τ, β, γ₁, γ₂, ω, c̃ bytes, packed sizes, key/sig sizes) match FIPS 204 final for ML-DSA-44/65/87, including `TRBYTES = 64` and `RNDBYTES = 32` (hedged signing).
- **Keygen**: correct domain separation `H(ξ ‖ k ‖ l)` per FIPS 204 (final), correct `power2round` split and `tr = H(pk)`.
- **Signing**: message binding `μ = H(tr ‖ M')` with `M' = (0, |ctx|, ctx, M)` and prehash variant `(1, |ctx|, ctx, OID, SHA-512(M))` ~~with correct per-mode OIDs~~; hedged `ρ' = H(K ‖ rnd ‖ μ)`; rejection bounds (γ₁−β, γ₂−β, γ₂, ω) all correct.
  > **Retracted in Round 2:** the OID bytes were wrong (and malformed DER),
  > and HashML-DSA does not use a per-mode OID at all — see R2-1.
- **Verification**: signature length enforced, `z` norm re-checked, hint-weight rules enforced, challenge equality via `subtle::ct_eq`. Safe API additionally validates `pk` length.
- **`unpack_sig` hint decoding**: enforces monotonically increasing indices, `end ≤ ω`, and zero padding — the strong-unforgeability (non-malleability) checks from the reference are all present.
- **Arithmetic** (`reduce.rs`, `rounding.rs`, `ntt.rs`, scalar path): Montgomery/Barrett reduction, `decompose` for both γ₂ branches, `make_hint`/`use_hint`, zetas table, and butterfly structure match the C reference. The NEON Montgomery lane math (`vshrn_n_s64::<32>` arithmetic shift-narrow) is correct.
- **Sampling**: `rej_uniform` (23-bit, `< Q`), `rej_eta` (mod-5 trick for η=2, `< 9` for η=4), `uniform_gamma1` via `polyz_unpack`, and SampleInBall (Fisher–Yates with sign bits) all match the reference; matrix nonce `(i≪8)+j` correct.
- **Constant-time posture**: consistent with the reference implementation — verification comparison is constant-time; signing's rejection-sampling branches are on values that are safe to leak by design. `chknorm` uses branchless absolute value. No secret-indexed table lookups found in the scalar path.
- **Supply chain**: only well-known RustCrypto/dalek-adjacent pure-Rust deps (`sha3`, `sha2`, `subtle`, `zeroize`, `getrandom`); no build.rs, no C bindings, wildcard deps denied.
- **Testing**: KAT tests replicate the C reference's `test_vectors.c` RNG and compare SHAKE256 hashes of pk/sk/sig bit-for-bit; multi-vector KAT covers 100 iterations × 3 modes; round-trip fuzz target asserts sign→verify success.

---

## Algebraic verification (2026-07-20)

The arithmetic layer was verified numerically with a bit-exact Python model of
the Rust integer semantics (i32/i64 wrapping, arithmetic shifts) —
`scripts/algebra_check.py`, rerunnable with
`python3 scripts/algebra_check.py src/ntt.rs`. **All 25 checks pass; no
algebraic divergences found.** What was proven:

- **Constants**: `Q·QINV ≡ 1 (mod 2³²)`; the inverse-NTT scaling factor
  `f = 41978 ≡ mont²/256 (mod Q)`.
- **`montgomery_reduce`**: `r ≡ a·2⁻³² (mod Q)` with `|r| < Q` over 200k
  random inputs spanning the full contract range `±2³¹·Q`, using exact
  wrapping-multiply semantics.
- **`reduce32`**: `r ≡ a (mod Q)`, `|r| ≤ 6283008` over the documented input
  range including both boundary values.
- **`caddq`**: branchless sign-mask semantics add Q exactly when negative.
- **`power2round`**: **exhaustive over all a ∈ [0, Q)** — the identity
  `a = a1·2¹³ + a0` with `a0 ∈ (−2¹², 2¹²]` holds for every field element.
- **`decompose`**: **exhaustive over all a ∈ [0, Q) for both γ₂ branches**
  (the ·1025≫22 and ·11275≫24 magic-constant divisions) — congruence
  `a ≡ a1·2γ₂ + a0 (mod Q)`, `a1` in range, `|a0| ≤ γ₂`.
- **Hint lemma** (the property signing/verification correctness rests on):
  with the exact usage pattern `h = MakeHint(w0 − u + v, w1)` under the
  rejection-check preconditions, `UseHint(w − u + v mod Q, h) = HighBits(w)`
  over 200k random cases for both γ₂ values.
- **`rej_eta` mod-5 trick**: `t − 5·((205t)≫10) = t mod 5` for all t < 15.
- **ZETAS table**: every entry satisfies `ZETAS[k] ≡ mont·1753^brv₈(k) (mod Q)`
  (Montgomery form of the 512th root of unity in bit-reversed order), `|z| < Q`.
- **NTT/INTT**: round-trip is a uniform scalar multiple with scalar exactly
  `2³² mod Q`, outputs in `(−Q, Q)`; NTT-based pointwise product matches a
  schoolbook negacyclic convolution in `Z_Q[X]/(X²⁵⁶+1)`.
- **AVX2 lane math**: the even/odd-lane `mul_epi32`/`srli`/mask/OR merge in
  `montgomery_mul_avx2` is lane-exact against scalar `montgomery_reduce`
  (50k random ±ζ, full-range i32 operands) — including the subtle point that
  a *logical* 64-bit right shift yields the correct truncated i32 for
  negative results.
- **NEON lane math**: `vmull`/`vmovn`/`vmul`/`vshrn` sequence lane-exact
  against scalar (50k random).
- **Overflow bounds**: `7Q` (L-fold Montgomery accumulation) is below the
  `reduce32` input limit; worst-case NTT coefficient growth `9Q < 2³¹`;
  `t1·2¹³ < 2³¹`; τ ≤ 64 sign bits in `SampleInBall`; `γ₁ − β > 0` for all
  modes.

One benign deviation was analyzed and accepted: after `caddq`, keygen's
`t = A·s1 + s2` can exceed `Q−1` by up to η before `power2round`. The
identity `a = a1·2¹³ + a0` still holds, `t1 ≤ 1023` still fits 10 bits, and
sign/verify consistently use the packed representative — behavior is
bit-identical to the C reference (confirmed by KATs).

## Recommended verification (run locally — this sandbox had no Rust toolchain)

```sh
cargo test --release                          # full test + KAT suite
cargo test --release --all-features           # expect F1 failure on x86_64
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check                              # expect F11 schema errors on modern cargo-deny
cargo +nightly fuzz run fuzz_unpack_sig -- -max_total_time=300
cargo build --no-default-features --target thumbv7em-none-eabihf
```

## Prioritized remediation order

1. F1 — fix or remove the broken AVX2 module (build is broken for `--all-features` on x86_64).
2. F2 — wire SIMD into `Poly::ntt` or drop the feature and the acceleration claims.
3. F3 — zeroize `key`, `s1`, `s2`, `t0`, `y`, `rhoprime`, and NTT copies in keygen/sign.
4. F4 — full sk↔pk consistency check in `from_keys`, or document the trust requirement.
5. F5/F6 — length-check low-level entry points; move the c̃ copy after rejection checks.
6. F7–F11 — documentation, fuzz-coverage, and tooling hygiene.

---

*This review is a best-effort static audit, not a formal verification or a certified evaluation. Constant-time properties were assessed at source level only; compiler optimizations can alter them — consider `dudect`-style or valgrind/ctgrind measurement on release builds.*
