//! Pure Rust implementation of ML-DSA (FIPS 204) / CRYSTALS-Dilithium.
//!
//! A post-quantum digital signature scheme standardized as FIPS 204.
//! Supports all three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.
//!
//! # Features
//!
//! - **FIPS 204 compliant** — supports pure ML-DSA and HashML-DSA (pre-hash)
//! - **`no_std` compatible** — works on embedded and WASM targets
//! - **WASM ready** — all dependencies support `wasm32-unknown-unknown`
//! - **Zeroize** — private key material is automatically zeroized on drop
//! - **Constant-time** — verification uses constant-time comparison
//! - **Optional serde** — enable the `serde` feature for serialization
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

