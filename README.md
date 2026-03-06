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
| NIST KAT vectors validated | ✅ |
| 0 `unsafe` blocks | ✅ |

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
```

### Signing & Verification

```rust
// Pure ML-DSA (§6.1)
let sig = kp.sign(b"message", b"context").unwrap();
let ok = DilithiumKeyPair::verify(kp.public_key(), &sig, b"message", b"context", ML_DSA_65);

// HashML-DSA pre-hash (§6.2) — message is SHA-512 hashed internally
let sig = kp.sign_prehash(b"large document", b"").unwrap();
let ok = DilithiumKeyPair::verify_prehash(kp.public_key(), &sig, b"large document", b"", ML_DSA_65);
```

### Serialization

```rust
// Key pair round-trip
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
dilithium-rs = { version = "0.1", features = ["serde"] }
```

```rust
let json = serde_json::to_string(&kp).unwrap();
let kp: DilithiumKeyPair = serde_json::from_str(&json).unwrap();
```

## `no_std` / WASM

```toml
[dependencies]
dilithium-rs = { version = "0.1", default-features = false }
```

All dependencies support `no_std` and `wasm32-unknown-unknown`:
- `sha3`, `sha2` — SHAKE/SHA hashing
- `subtle` — constant-time comparison
- `zeroize` — secret material cleanup
- `getrandom` — OS entropy (uses `crypto.getRandomValues` in WASM)

## Security

- **0 `unsafe` blocks** in production code
- **Constant-time** verification via `subtle::ConstantTimeEq`
- **Zeroize** — private keys auto-zeroed on drop, seeds/rnd zeroed after use
- **NIST KAT** — bit-for-bit match with C reference (pk, sk, sig hashes)
- **Key validation** — `from_keys()` validates rho consistency + `tr = H(pk)`

## Test Suite

```
cargo test                              # all 63 tests
cargo test --features serde             # with serde
cargo clippy -- -W clippy::pedantic     # 0 warnings
```

| Suite | Tests | What |
|-------|-------|------|
| Unit | 25 | NTT, reduce, rounding, symmetric, poly |
| Round-trip | 17 | Sign/verify all modes, HashML-DSA, key validation |
| Coverage | 17 | Edge cases, error paths, boundaries |
| KAT | 2 | Bit-for-bit match with C reference |
| Doc-tests | 2 | Code examples compile and run |

## License

MIT
