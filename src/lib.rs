//! Pure Rust implementation of ML-DSA (FIPS 204) / CRYSTALS-Dilithium.
//!
//! A post-quantum digital signature scheme standardized as FIPS 204.
//! Supports all three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.
//!
//! # Features
//!
//! - **FIPS 204 compliant** — supports pure ML-DSA and HashML-DSA (pre-hash)
//! - **`no_std` compatible** — works on embedded and WASM targets
//! - **WASM ready** — enable the `js` feature for browser environments
//! - **Zeroize** — private key material, sampling buffers and packing
//!   temporaries are zeroized; `Debug` redacts the private key
//! - **Constant-time** — constant-time challenge comparison in verification,
//!   plus branchless norm and hint checks in signing (stronger than the C
//!   reference, which short-circuits both)
//! - **Bring your own RNG** — `generate_with_rng` / `sign_with_rng` work
//!   without `getrandom`, for `no_std` targets with their own entropy source
//! - **Validated key import** — `from_keys`, `from_bytes` and serde
//!   `Deserialize` recompute `t = A·s1 + s2` and reject tampered secret keys
//! - **Optional serde** — enable the `serde` feature for serialization
//! - **SIMD acceleration** — AVX2 (x86_64) and NEON (AArch64) NTT behind `simd`
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std`   | ✅      | Enables `getrandom` for OS entropy (`generate`, `sign`, `sign_prehash`) |
//! | `serde` | ❌      | Enables `Serialize`/`Deserialize` for key pairs, signatures, and modes |
//! | `simd`  | ❌      | Enables AVX2 (x86_64) and NEON (AArch64) NTT acceleration |
//! | `js`    | ❌      | Enables `getrandom/js` for WASM browser targets |
//!
//! # Platform Support
//!
//! | Target | Build | Notes |
//! |--------|-------|-------|
//! | x86_64 Linux/macOS | ✅ | Full support, AVX2 SIMD optional |
//! | AArch64 (Apple Silicon, ARM) | ✅ | Full support, NEON SIMD optional |
//! | `wasm32-unknown-unknown` | ✅ | Requires `--no-default-features`, add `js` for entropy |
//! | `thumbv7em-none-eabihf` | ✅ | Requires `--no-default-features`, deterministic APIs only |
//!
//! # Quick Start
//!
//! ```rust
//! use dilithium::{MlDsaKeyPair, ML_DSA_44};
//!
//! let kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();
//! let sig = kp.sign(b"Hello, post-quantum world!", b"").unwrap();
//! assert!(MlDsaKeyPair::verify(
//!     kp.public_key(), &sig, b"Hello, post-quantum world!", b"",
//!     ML_DSA_44
//! ));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
// Crypto-specific clippy allows:
// - unreadable_literal: NTT zetas table ported verbatim from C reference
// - cast_possible_truncation/sign_loss/wrap: intentional in bit-packing (poly.rs, packing.rs)
// - cast_lossless: i32→i64 / u8→i32 casts are clearer as `as` in arithmetic
// - many_single_char_names: math variable names (e, r, t, w, z) from the FIPS spec
// - wildcard_imports: used for re-exporting poly/polyvec helpers
// - identity_op: shifts by 0 are from the C reference for clarity
// - too_many_arguments: pack_sk/unpack_sk mirror the C API
// - module_name_repetitions: DilithiumMode etc. are the standard naming
#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::wildcard_imports,
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::needless_range_loop,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

extern crate alloc;

// ── Internal modules (accessible but not in public docs) ────────
#[doc(hidden)]
pub mod ntt;
#[cfg(feature = "simd")]
pub mod ntt_avx2;
#[cfg(feature = "simd")]
pub mod ntt_neon;
#[doc(hidden)]
pub mod packing;
pub mod params;
#[doc(hidden)]
pub mod poly;
#[doc(hidden)]
pub mod polyvec;
#[doc(hidden)]
pub mod reduce;
#[doc(hidden)]
pub mod rounding;
pub mod safe_api;
#[doc(hidden)]
pub mod sign;
#[doc(hidden)]
pub mod symmetric;

// ── Public re-exports (the SDK surface) ─────────────────────────
pub use params::DilithiumMode;
pub use params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
pub use safe_api::{DilithiumError, DilithiumKeyPair, DilithiumSignature};

/// FIPS 204 type alias for `DilithiumKeyPair`.
pub use safe_api::MlDsaKeyPair;
/// FIPS 204 type alias for `DilithiumSignature`.
pub use safe_api::MlDsaSignature;
