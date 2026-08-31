# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :x:                |
| < 0.3   | :x:                |

> **0.3.x and earlier produced non-conforming HashML-DSA signatures** (the
> wrong OID in the pre-hash message representative — see `SECURITY_AUDIT.md`
> R2-1). Pure ML-DSA was unaffected. Upgrade to 0.4.x for interoperable
> `sign_prehash`/`verify_prehash`.

## Reporting a Vulnerability

If you discover a security vulnerability in `dilithium-rs`, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **latticesafe@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgment within **48 hours**.
4. We will work with you to understand and address the issue before any public
   disclosure.

## Security Considerations

### What this crate provides

- **FIPS 204 (ML-DSA)** compliant signing and verification, checked against
  the official NIST ACVP `keyGen`/`sigGen`/`sigVer` vectors (pure and
  SHA-512 HashML-DSA) and the pq-crystals C-reference KATs
- **Constant-time** signature verification via `subtle::ConstantTimeEq`
- **Automatic zeroization** of private key material on drop (`zeroize`),
  including the SHAKE output buffers that carry `s1`/`s2` and the mask `y`,
  the packing temporaries, the pointwise accumulator, and the **Keccak sponge
  state itself** (`src/shake.rs` implements SHAKE on the `keccak`
  permutation so the state can be wiped; the `sha3` crate does not expose
  it)
- **Redacting `Debug`** — printing a key pair never emits private key bytes
- **Validated key import** — `from_keys`, `from_bytes` and serde
  `Deserialize` all recompute `t = A·s1 + s2` and reject tampered secret keys
- **No `unsafe` blocks** in the core library (SIMD modules use `unsafe`
  behind the `simd` feature flag)
- **Zero external C dependencies** — pure Rust implementation

### What this crate does NOT provide

- **Certified FIPS 204 module** — This implementation has not been submitted
  for CMVP validation. Do not use it where a certified module is required.
- **Fully side-channel hardened signing** — The rejection-sampling *loop
  count* is inherently data-dependent (as in every ML-DSA implementation).
  The per-coefficient checks that the C reference short-circuits are
  branchless here: `chknorm` scans without early exit and `make_hint` is
  fully masked, so neither the position of an out-of-bound coefficient in a
  rejected candidate nor the sign of a secret `w0` coefficient is exposed.
  Constant-time properties were reviewed at source level only — compiler
  optimizations can alter them.
- **A formal proof of the scheme** — The arithmetic layer *is* machine-checked
  (Kani bounded model checking of the reduction, rounding and unpacking
  contracts, plus exhaustive verification over complete finite domains — see
  `src/verification.rs` and `examples/exhaustive_proofs.rs`), but the signing
  and verification protocol as a whole is not mechanically proven, and the
  security reduction is not formalized.
- **Hardware-backed key storage** — Key material lives in process memory.
  Use HSMs or secure enclaves for high-value keys.

### Recommended usage

```rust
use dilithium::{MlDsaKeyPair, ML_DSA_65};

// Generate keys — use ML-DSA-65 (NIST Level 3) or ML-DSA-87 (Level 5)
// for production. ML-DSA-44 (Level 2) is suitable for most applications.
let kp = MlDsaKeyPair::generate(ML_DSA_65).unwrap();

// Keys are automatically zeroized when dropped
drop(kp);
```

### Dependencies

All dependencies are pure Rust with no C bindings:

| Crate | Purpose |
|-------|---------|
| `keccak` | Keccak-f\[1600\] permutation (the SHAKE sponge is in this crate, so its state can be zeroized) |
| `sha2` | SHA-512 (HashML-DSA pre-hash) |
| `subtle` | Constant-time comparison |
| `zeroize` | Secure memory zeroing |
| `getrandom` | OS entropy (optional, behind `std` feature) |

Targets without `getrandom` can supply their own entropy through
`generate_with_rng` / `sign_with_rng` / `sign_prehash_with_rng`.
