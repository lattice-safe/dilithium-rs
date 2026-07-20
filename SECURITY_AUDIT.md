# Security Audit — dilithium-rs v0.2.0

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
- **Signing**: message binding `μ = H(tr ‖ M')` with `M' = (0, |ctx|, ctx, M)` and prehash variant `(1, |ctx|, ctx, OID, SHA-512(M))` with correct per-mode OIDs; hedged `ρ' = H(K ‖ rnd ‖ μ)`; rejection bounds (γ₁−β, γ₂−β, γ₂, ω) all correct.
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
