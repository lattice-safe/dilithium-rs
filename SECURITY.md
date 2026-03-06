# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `dilithium-rs`, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **security@lattice-safe.dev** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgment within **48 hours**.
4. We will work with you to understand and address the issue before any public
   disclosure.

## Security Considerations

### What this crate provides

- **FIPS 204 (ML-DSA)** compliant signing and verification
- **Constant-time** signature verification via `subtle::ConstantTimeEq`
- **Automatic zeroization** of private key material on drop (`zeroize`)
- **No `unsafe` blocks** in the core library (SIMD modules use `unsafe`
  behind the `simd` feature flag)
- **Zero external C dependencies** — pure Rust implementation

### What this crate does NOT provide

- **Certified FIPS 204 module** — This implementation has not been submitted
  for CMVP validation. Do not use it where a certified module is required.
- **Side-channel hardened signing** — While verification is constant-time,
  the signing path uses rejection sampling with data-dependent branches
  (matching the reference implementation).
- **Formal verification** — The implementation is a faithful port of the
  C reference but has not been formally verified.
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
| `sha3` | SHAKE-128/256, SHA3 |
| `sha2` | SHA-512 (HashML-DSA pre-hash) |
| `subtle` | Constant-time comparison |
| `zeroize` | Secure memory zeroing |
| `getrandom` | OS entropy (optional, behind `std` feature) |
