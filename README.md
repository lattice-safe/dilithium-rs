# dilithium-rs

> **Pure Rust implementation of ML-DSA (FIPS 204) / CRYSTALS-Dilithium**
>
> Post-quantum digital signature scheme — `no_std` + WASM ready.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

| Feature | Status |
|---------|--------|
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | ✅ |
| Pure ML-DSA signing (§6.1) | ✅ |
| HashML-DSA pre-hash mode (§6.2) | ✅ |
| Key validation (§7.1) | ✅ |
| Constant-time verification | ✅ |
| Zeroization of secrets | ✅ |
| `no_std` / WASM compatible | ✅ |
| Optional `serde` support | ✅ |
| NIST ACVP conformance vectors (keyGen / sigGen / sigVer) | ✅ |
| C-reference KAT — bit-for-bit, 100 vectors × 3 modes | ✅ |
| SIMD acceleration (AVX2 + NEON) | ✅ |
| Bring-your-own-RNG (`no_std` friendly) | ✅ |
| 0 `unsafe` blocks (core library) | ✅ |
| 100% region / line / function test coverage (excl. per-arch SIMD) | ✅ |

## Quick Start

```rust
use dilithium::{MlDsaKeyPair, ML_DSA_44};

// Generate a key pair
let kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();

// Sign a message
let sig = kp.sign(b"Hello, post-quantum world!", b"").unwrap();

// Verify
assert!(MlDsaKeyPair::verify(
    kp.public_key(), &sig,
    b"Hello, post-quantum world!", b"",
    ML_DSA_44
));
```

## Security Levels

| FIPS 204 Name | NIST Level | Public Key | Secret Key | Signature |
|---------------|------------|------------|------------|-----------|
| ML-DSA-44     | 2          | 1,312 B    | 2,560 B    | 2,420 B   |
| ML-DSA-65     | 3          | 1,952 B    | 4,032 B    | 3,309 B   |
| ML-DSA-87     | 5          | 2,592 B    | 4,896 B    | 4,627 B   |

## API Reference

### Key Generation

```rust
use dilithium::{DilithiumKeyPair, ML_DSA_65};

// Random key pair (OS entropy)
let kp = DilithiumKeyPair::generate(ML_DSA_65).unwrap();

// Deterministic key pair (from seed)
let seed = [0u8; 32];
let kp = DilithiumKeyPair::generate_deterministic(ML_DSA_65, &seed);

// Caller-supplied entropy (works without the `std`/`getrandom` feature)
let kp = DilithiumKeyPair::generate_with_rng(ML_DSA_65, &mut |buf| {
    my_rng_fill(buf).map_err(|_| ())
}).unwrap();
```

A failing entropy source returns `DilithiumError::RandomError` and produces
no key or signature — hedged signing never silently falls back to a
zero `rnd`. `sign_with_rng` / `sign_prehash_with_rng` take the same hook.

### Signing & Verification

```rust
// Pure ML-DSA (§6.1)
let sig = kp.sign(b"message", b"context").unwrap();
let ok = DilithiumKeyPair::verify(kp.public_key(), &sig, b"message", b"context", ML_DSA_65);

// HashML-DSA pre-hash (§6.2) — message is SHA-512 hashed internally
let sig = kp.sign_prehash(b"large document", b"").unwrap();
let ok = DilithiumKeyPair::verify_prehash(kp.public_key(), &sig, b"large document", b"", ML_DSA_65);
```

The pre-hash message representative is built exactly as FIPS 204 Algorithm 4
specifies — `0x01 || len(ctx) || ctx || OID || SHA-512(M)`, where `OID` is the
DER encoding of the *SHA-512* object identifier `2.16.840.1.101.3.4.2.3`
(11 bytes, identical for all three parameter sets). The per-parameter-set
`id-ml-dsa-*` / `id-hash-ml-dsa-*-with-sha512` identifiers are exposed
separately (`mode.algorithm_oid()`, `mode.hash_algorithm_oid()`) for use in
X.509 / CMS structures; they are **not** part of the signature computation.

### Serialization

```rust
// Key pair round-trip. to_bytes() returns Zeroizing<Vec<u8>> — the buffer
// holds the plaintext private key and is wiped on drop.
let bytes = kp.to_bytes();          // [mode_tag | pk | sk]
let kp2 = DilithiumKeyPair::from_bytes(&bytes).unwrap();

// Public key export (for distribution)
let pk_bytes = kp.public_key_bytes(); // [mode_tag | pk]
let (mode, pk) = DilithiumKeyPair::from_public_key(&pk_bytes).unwrap();

// Signature round-trip
let sig_bytes = sig.as_bytes().to_vec();
let sig2 = DilithiumSignature::from_bytes(sig_bytes);

// Import raw keys with validation (FIPS 204 §7.1)
let kp = DilithiumKeyPair::from_keys(sk_bytes, pk_bytes, ML_DSA_65).unwrap();
```

### Serde (optional)

```toml
[dependencies]
dilithium-rs = { version = "0.4", features = ["serde"] }
```

```rust
let json = serde_json::to_string(&kp).unwrap();
let kp: DilithiumKeyPair = serde_json::from_str(&json).unwrap();
```

`Serialize` writes the private key in **plaintext** — only serialize into
protected storage. `Deserialize` runs the full FIPS 204 §7.1 key validation,
so a deserialized key pair satisfies the same invariants as one built by a
constructor (a tampered or wrong-length key is rejected, not silently
accepted). `Debug` redacts the private key.

## `no_std` / WASM

```toml
[dependencies]
dilithium-rs = { version = "0.4", default-features = false }
```

All dependencies support `no_std` and `wasm32-unknown-unknown`:
- `keccak` — Keccak-f[1600] permutation (the SHAKE sponge lives in this
  crate so its state can be zeroized)
- `sha2` — SHA-512 for the HashML-DSA pre-hash
- `subtle` — constant-time comparison
- `zeroize` — secret material cleanup
- `getrandom` — OS entropy (uses `crypto.getRandomValues` in WASM)

## Benchmarks

Re-measured for 0.4.0 on an idle Apple M1 Max (macOS 26.5, rustc 1.93 nightly,
Apple clang 21). Rust: Criterion point estimate, default features (no `simd`).
C: the pq-crystals `ref/` implementation built with `cc -O3
-fomit-frame-pointer`, mean over 20,000 iterations. Each side was run three
times alternately; the table reports the **median** of the three, because
run-to-run drift on a laptop is larger than most of the differences being
compared (observed spread: Rust ≤ 5%, C ≤ 12%).

| Operation | Mode | Rust (µs) | C ref (µs) | Ratio |
|-----------|------|-----------|-----------|-------|
| keygen | ML-DSA-44 | 54.3 | 53.5 | 1.02× |
| keygen | ML-DSA-65 | 87.9 | 104.2 | **0.84×** ✅ |
| keygen | ML-DSA-87 | 137.5 | 148.5 | **0.93×** ✅ |
| sign | ML-DSA-44 | 179.3 | 249.7 | **0.72×** ✅ |
| sign | ML-DSA-65 | 284.0 | 397.9 | **0.71×** ✅ |
| sign | ML-DSA-87 | 347.1 | 487.9 | **0.71×** ✅ |
| verify | ML-DSA-44 | 52.3 | 62.7 | **0.83×** ✅ |
| verify | ML-DSA-65 | 82.3 | 97.1 | **0.85×** ✅ |
| verify | ML-DSA-87 | 134.2 | 162.1 | **0.83×** ✅ |

Ratios below 1.0 mean Rust is faster. Both harnesses run the **same**
methodology, which differs from the pre-0.4.0 table:

- **The signed message varies per iteration.** With a fixed `(sk, msg, rnd)`
  the rejection loop is deterministic, so the old figures reported the
  rejection count of one arbitrary case — which is why ML-DSA-65 previously
  looked 1.5× slower than C. Varying the message samples the distribution.
- **No entropy syscall inside the measured region** on either side: the Rust
  bench passes a fixed `rnd`, and the C harness links a deterministic
  `randombytes` stub in place of `ref/randombytes.c` (which reads
  `/dev/urandom`).
- Both use the ctx-level API with `ctx = ""` and a 1024-byte message.

The gap is dominated by the SHAKE implementation, since Dilithium spends most
of its time in Keccak: this crate's sponge (`src/shake.rs`) sits on the
RustCrypto `keccak` permutation, absorbing and squeezing whole 64-bit lanes,
while the reference uses its bundled `fips202.c`. Replacing the `sha3` crate
with that sponge in 0.4.0 (so the state could be zeroized — see
`SECURITY_AUDIT.md` R2-12) also improved every ratio by a few points, which
was not the goal but is welcome. The comparison is against the reference
`ref/` code, **not** the hand-optimized AVX2 variant.

```bash
cargo bench --bench dilithium_bench     # run benchmarks
```

## Security

- **0 `unsafe` blocks** in core library (SIMD modules use `unsafe` behind `simd` feature)
- **Constant-time** verification via `subtle::ConstantTimeEq`
- **Zeroize** — private keys auto-zeroed on drop, seeds/rnd zeroed after use
- **NIST ACVP conformance** — official NIST vectors for `keyGen`, `sigGen`
  (pure + SHA-512 HashML-DSA) and `sigVer`, including NIST's negative cases
  (modified message, `c̃`, hint, `z`). The deterministic HashML-DSA vectors
  reproduce byte-for-byte, which is what proves the pre-hash `M'` — OID
  included — is interoperable and not merely self-consistent
- **C-reference KAT** — bit-for-bit match with the pq-crystals reference
  (pk, sk, sig hashes; 100 vectors × 3 modes)
- **Key validation** — `from_keys()` / `from_bytes()` / serde `Deserialize`
  recompute `t = A·s1 + s2` and reject tampered secret keys
- **Branchless norm and hint checks** — `chknorm` scans every coefficient
  without early exit and `make_hint` is fully masked, so neither the position
  of an out-of-bound coefficient in a rejected candidate nor the sign of a
  secret `w0` coefficient is exposed through timing (this goes beyond the C
  reference, which short-circuits both)
- **No secret residue** — the SHAKE output buffers that carry `s1`/`s2` and
  the mask `y`, the pack temporaries, and the pointwise accumulator are all
  zeroized; `Debug` on a key pair prints `[REDACTED]`
- **Fuzz tested** — 4 targets (key/signature decoding, sign→verify
  round-trip, adversarial verification). The three original targets have
  41M+ cumulative executions with 0 crashes; `fuzz_verify` is new in 0.4.0

See [SECURITY.md](SECURITY.md) for responsible disclosure and scope.

## Test Suite

```
cargo test --all-features               # all 156 tests
cargo test --features serde             # with serde
cargo test --features simd              # with SIMD (AVX2 / NEON kernels)
cargo clippy --all-targets --all-features -- -D warnings  # 0 warnings
```

Verification beyond the test suite:

```
cargo run --release --example exhaustive_proofs  # complete finite domains
cargo kani                                      # bounded model checking
cargo run --release --example timing_check       # dudect timing measurement
./scripts/test-avx2-docker.sh                    # AVX2 kernels under QEMU
python3 scripts/algebra_check.py src/ntt.rs      # bit-exact arithmetic model
```

| Suite | Tests | What |
|-------|-------|------|
| Unit | 50 | NTT, reduce, rounding, SHAKE-vs-`sha3` at every rate boundary, poly, both SIMD dispatch arms vs scalar, sampler refill paths, RNG-failure and `Debug` redaction |
| API coverage | 33 | Error `Display`, mode tags, serialization error paths, hint decodings, bring-your-own-RNG |
| Coverage | 20 | Edge cases, error paths, boundaries, OID DER encoding, in-place vs out-of-place kernels |
| **ACVP** | **5** | **Official NIST vectors: 75 keyGen, 12 pure sigGen (ctx 0–245 B), SHA-512 HashML-DSA sigGen/verify, 19 sigVer incl. all four negative reasons** |
| HashML-DSA conformance | 6 | `M'` bytes pinned against FIPS 204 Algorithm 4/5, domain separation |
| KAT | 4 | Bit-for-bit match with C reference (all 3 modes) |
| Multi-vector KAT | 3 | 100 vectors × 3 modes accumulated hash |
| Rejection paths | 3 | The `‖c·t0‖∞ ≥ γ₂` rejection branch and loop termination |
| Round-trip | 23 | Sign/verify all modes, HashML-DSA, key validation, low-level guards |
| Serde coverage | 7 | Round-trips plus validated-deserialization rejections |
| Doc-tests | 2 | Code examples compile and run |

ACVP vectors live in `tests/data/acvp_ml_dsa.json`, extracted from the NIST
ACVP server's `ML-DSA-{keyGen,sigGen,sigVer}-FIPS204` test data. Only SHA-512
pre-hash vectors are exercised — the other approved pre-hash functions
(SHA-256, SHA3-\*, SHAKE-\*) are not implemented.

**Coverage: 100% of regions, lines and functions**
(`cargo llvm-cov --all-features`, enforced at 100% in CI), excluding
`src/ntt_avx2.rs` and `src/ntt_neon.rs` — per-architecture code cannot be
fully covered from a single machine. Those kernels are instead verified by
SIMD-vs-scalar equivalence tests plus the full KAT suite, on both
architectures, and both arms of the runtime dispatch (accelerated and scalar
fallback) are tested explicitly.

### Docker

Build and run the full suite in a minimal Alpine (musl) container — no local
Rust toolchain required:

```bash
docker build -t dilithium-rs-test .      # rust:1-alpine base, pure-Rust deps
docker run --rm dilithium-rs-test        # cargo test --all-features (default)
docker run --rm -it dilithium-rs-test sh # interactive shell
```

Measure coverage in a glibc container (mirrors the CI job):

```bash
docker build -f Dockerfile.coverage -t dilithium-rs-coverage .
docker run --rm dilithium-rs-coverage    # cargo llvm-cov --all-features, 100% gate
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | ✅      | OS entropy for `generate`, `sign`, `sign_prehash` |
| `serde` | ❌      | `Serialize`/`Deserialize` for key pairs and signatures |
| `simd`  | ❌      | AVX2 (x86_64) and NEON (AArch64) NTT acceleration |
| `js`    | ❌      | `getrandom/js` for WASM browser targets |

## Verification Status

What has been checked, and how — so the claims above can be weighed rather
than taken on faith. Details in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

| Area | Status |
|------|--------|
| FIPS 204 conformance, pure ML-DSA | Official NIST ACVP keyGen/sigGen/sigVer vectors pass; bit-for-bit match with the pq-crystals C reference over 100 vectors × 3 modes |
| FIPS 204 conformance, HashML-DSA (SHA-512) | Official NIST ACVP vectors pass, byte-for-byte on the deterministic cases (fixed in 0.4.0 — earlier versions embedded the wrong OID) |
| Arithmetic layer, exhaustive | `power2round`, `decompose` and `use_hint` verified over **all 8,380,417 field elements**; `make_hint` over every reachable `(a0, a1)`; every packer over every coefficient value; the hint lemma the scheme rests on — `cargo run --release --example exhaustive_proofs` |
| Arithmetic layer, formal | Kani bounded model checking of the same contracts *symbolically*, plus absence of panics/overflow/OOB, plus the unpackers' output ranges for arbitrary attacker-supplied bytes — 13 harnesses discharge; `cargo kani` |
| Constant time | dudect-style measurement of the branchless `chknorm` and `make_hint` against the reference short-circuiting forms as positive controls: the `chknorm` control fires at \|t\| ≈ 16,000 while the shipped version stays under \|t\| = 1. The `make_hint` control does *not* fire — LLVM already compiles the reference short-circuit branchlessly on aarch64, so there was nothing to detect on this target |
| Test coverage | 100% of regions, lines and functions (`cargo llvm-cov --all-features`), enforced in CI. The two per-architecture SIMD modules are excluded from the gate: on any one machine, another architecture's kernels — and its tests — are unreachable code. Their correctness is covered by the SIMD-vs-scalar equivalence tests and the KAT suite, run on both x86_64 and aarch64 |
| Memory safety | 34 adversarial public-API cases produce no panic; all `unsafe` is confined to the SIMD NTT and reviewed for feature-gating, bounds and aliasing |
| SIMD kernels | NEON exercised locally (full KAT suite through the SIMD path); AVX2 exercised under QEMU via `./scripts/test-avx2-docker.sh`, and in CI on the x86_64 runner |
| Fuzzing | 4 targets, ~1.1 billion executions in this round (8 min each), no crashes and no hangs. Note: `cargo fuzz` must be run with `--sanitizer=none` on macOS 26 — see `fuzz/README.md` |
| Secret hygiene | Key material, sampling buffers, packing temporaries and the Keccak sponge state are all zeroized; `Debug` redacts the private key |
| API stability | `cargo semver-checks` against 0.3.0: one breaking change detected (`DilithiumMode::hash_oid` removed), covered by the major bump |

Known gaps, stated plainly:

- **Not CMVP-validated.** Do not use where a certified module is required.
- **The scheme as a whole is not mechanically proven.** The arithmetic layer
  is (see above), but the signing/verification protocol and the security
  reduction are not formalized.
- **Pre-hash support is SHA-512 only.** FIPS 204 also approves SHA-256,
  SHA3-\* and SHAKE-\*; ACVP vectors for those are skipped, not failed.
- **Constant-time evidence is statistical, not a proof.** "No leak detected"
  bounds what the sample size could see; it is not a guarantee, and a
  different compiler or target may differ.
- **No CMVP-style operational testing** of the RNG, key storage or
  parameter selection — those are the caller's responsibility.

## License

MIT
