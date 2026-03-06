//! High-level safe Rust SDK for ML-DSA (FIPS 204) / CRYSTALS-Dilithium.
//!
//! Supports both **pure ML-DSA** (§6.1) and **HashML-DSA** (§6.2) modes.
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
//!
//! # Security Levels
//!
//! | FIPS 204 Name | NIST Level | Public Key | Secret Key | Signature |
//! |---------------|------------|------------|------------|-----------|
//! | ML-DSA-44     | 2          | 1312 B     | 2560 B     | 2420 B    |
//! | ML-DSA-65     | 3          | 1952 B     | 4032 B     | 3309 B    |
//! | ML-DSA-87     | 5          | 2592 B     | 4896 B     | 4627 B    |

use alloc::{vec, vec::Vec};
use core::fmt;

#[cfg(feature = "getrandom")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub use crate::params::DilithiumMode;
use crate::params::*;
use crate::sign;
use crate::symmetric::shake256;

/// Errors returned by the ML-DSA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DilithiumError {
    /// Random number generation failed.
    RandomError,
    /// Invalid key or signature format.
    FormatError,
    /// Signature verification failed.
    BadSignature,
    /// An argument was invalid (e.g. context > 255 bytes).
    BadArgument,
    /// Key validation failed (§7.1).
    InvalidKey,
}

impl fmt::Display for DilithiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomError => write!(f, "random number generation failed"),
            Self::FormatError => write!(f, "invalid format"),
            Self::BadSignature => write!(f, "invalid signature"),
            Self::BadArgument => write!(f, "invalid argument"),
            Self::InvalidKey => write!(f, "key validation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DilithiumError {}

/// An ML-DSA key pair (private key + public key).
///
/// The private key bytes are **automatically zeroized on drop** (FIPS 204 §7).
///
/// Type aliases: `MlDsaKeyPair` (FIPS 204 naming) = `DilithiumKeyPair` (legacy).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DilithiumKeyPair {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_zeroizing::serialize",
            deserialize_with = "serde_zeroizing::deserialize"
        )
    )]
    privkey: Zeroizing<Vec<u8>>,
    pubkey: Vec<u8>,
    mode: DilithiumMode,
}

/// Helper module for serde on `Zeroizing<Vec<u8>>`.
#[cfg(feature = "serde")]
mod serde_zeroizing {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        // Deref to &Vec<u8> which implements Serialize
        let inner: &Vec<u8> = val;
        inner.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        Ok(Zeroizing::new(v))
    }
}

/// FIPS 204 name alias for `DilithiumKeyPair`.
pub type MlDsaKeyPair = DilithiumKeyPair;

/// An ML-DSA / Dilithium signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DilithiumSignature {
    data: Vec<u8>,
}

/// FIPS 204 name alias for `DilithiumSignature`.
pub type MlDsaSignature = DilithiumSignature;

impl DilithiumKeyPair {
    /// Generate a new key pair using OS entropy (FIPS 204 §6.1 `KeyGen`).
    ///
    /// Requires the `std` or `getrandom` feature (enabled by default).
    #[cfg(feature = "getrandom")]
    pub fn generate(mode: DilithiumMode) -> Result<Self, DilithiumError> {
        let mut seed = [0u8; SEEDBYTES];
        getrandom(&mut seed).map_err(|()| DilithiumError::RandomError)?;
        let result = Self::generate_deterministic(mode, &seed);
        seed.zeroize();
        Ok(result)
    }

    /// Generate a key pair deterministically from a seed.
    #[must_use]
    pub fn generate_deterministic(mode: DilithiumMode, seed: &[u8; SEEDBYTES]) -> Self {
        let (pk, sk) = sign::keypair(mode, seed);
        DilithiumKeyPair {
            privkey: Zeroizing::new(sk),
            pubkey: pk,
            mode,
        }
    }

    /// Sign a message using pure ML-DSA (FIPS 204 §6.1 ML-DSA.Sign).
    ///
    /// Context string `ctx` is optional (max 255 bytes).
    /// Requires the `std` or `getrandom` feature for randomized signing.
    #[cfg(feature = "getrandom")]
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<DilithiumSignature, DilithiumError> {
        if ctx.len() > 255 {
            return Err(DilithiumError::BadArgument);
        }

        let mut rnd = [0u8; RNDBYTES];
        getrandom(&mut rnd).map_err(|()| DilithiumError::RandomError)?;

        let mut sig = vec![0u8; self.mode.signature_bytes()];
        let ret = sign::sign_signature(self.mode, &mut sig, msg, ctx, &rnd, &self.privkey);
        rnd.zeroize();

        if ret != 0 {
            return Err(DilithiumError::BadArgument);
        }

        Ok(DilithiumSignature { data: sig })
    }

    /// Sign a message using HashML-DSA (FIPS 204 §6.2 HashML-DSA.Sign).
    ///
    /// The message is internally hashed with SHA-512 before signing.
    /// Context string `ctx` is optional (max 255 bytes).
    /// Requires the `std` or `getrandom` feature for randomized signing.
    #[cfg(feature = "getrandom")]
    pub fn sign_prehash(
        &self,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<DilithiumSignature, DilithiumError> {
        if ctx.len() > 255 {
            return Err(DilithiumError::BadArgument);
        }

        let mut rnd = [0u8; RNDBYTES];
        getrandom(&mut rnd).map_err(|()| DilithiumError::RandomError)?;

        let mut sig = vec![0u8; self.mode.signature_bytes()];
        let ret = sign::sign_hash(self.mode, &mut sig, msg, ctx, &rnd, &self.privkey);
        rnd.zeroize();

        if ret != 0 {
            return Err(DilithiumError::BadArgument);
        }

        Ok(DilithiumSignature { data: sig })
    }

    /// Sign deterministically (for testing / reproducibility).
    pub fn sign_deterministic(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; RNDBYTES],
    ) -> Result<DilithiumSignature, DilithiumError> {
        if ctx.len() > 255 {
            return Err(DilithiumError::BadArgument);
        }

        let mut sig = vec![0u8; self.mode.signature_bytes()];
        sign::sign_signature(self.mode, &mut sig, msg, ctx, rnd, &self.privkey);
        Ok(DilithiumSignature { data: sig })
    }

    /// Verify a pure ML-DSA signature (FIPS 204 §6.1 ML-DSA.Verify).
    #[must_use]
    pub fn verify(
        pk: &[u8],
        sig: &DilithiumSignature,
        msg: &[u8],
        ctx: &[u8],
        mode: DilithiumMode,
    ) -> bool {
        if pk.len() != mode.public_key_bytes() {
            return false;
        }
        if sig.data.len() != mode.signature_bytes() {
            return false;
        }
        sign::verify(mode, &sig.data, msg, ctx, pk)
    }

    /// Verify a HashML-DSA signature (FIPS 204 §6.2 HashML-DSA.Verify).
    #[must_use]
    pub fn verify_prehash(
        pk: &[u8],
        sig: &DilithiumSignature,
        msg: &[u8],
        ctx: &[u8],
        mode: DilithiumMode,
    ) -> bool {
        if pk.len() != mode.public_key_bytes() {
            return false;
        }
        if sig.data.len() != mode.signature_bytes() {
            return false;
        }
        sign::verify_hash(mode, &sig.data, msg, ctx, pk)
    }

    /// Get the encoded public key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// Get the encoded private key bytes.
    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        &self.privkey
    }

    /// Get the security mode.
    #[must_use]
    pub fn mode(&self) -> DilithiumMode {
        self.mode
    }

    /// Reconstruct from private + public key bytes with validation (FIPS 204 §7.1).
    ///
    /// Validates that:
    /// 1. Key sizes match the expected values for the given mode.
    /// 2. The public key embedded in the secret key is consistent.
    /// 3. The secret key's `tr = H(pk)` field is consistent.
    pub fn from_keys(
        privkey: &[u8],
        pubkey: &[u8],
        mode: DilithiumMode,
    ) -> Result<Self, DilithiumError> {
        // Check sizes
        if privkey.len() != mode.secret_key_bytes() {
            return Err(DilithiumError::FormatError);
        }
        if pubkey.len() != mode.public_key_bytes() {
            return Err(DilithiumError::FormatError);
        }

        // FIPS 204 §7.1: Validate key consistency
        // The secret key starts with rho (SEEDBYTES) which must match
        // the public key's rho
        let sk_rho = &privkey[..SEEDBYTES];
        let pk_rho = &pubkey[..SEEDBYTES];
        if sk_rho != pk_rho {
            return Err(DilithiumError::InvalidKey);
        }

        // Validate tr = H(pk) — tr is at offset 2*SEEDBYTES in sk layout: (rho, key, tr, ...)
        let tr_offset = 2 * SEEDBYTES;
        let sk_tr = &privkey[tr_offset..tr_offset + TRBYTES];
        let mut expected_tr = [0u8; TRBYTES];
        shake256(&mut expected_tr, pubkey);
        if sk_tr != &expected_tr[..] {
            return Err(DilithiumError::InvalidKey);
        }

        Ok(DilithiumKeyPair {
            privkey: Zeroizing::new(privkey.to_vec()),
            pubkey: pubkey.to_vec(),
            mode,
        })
    }

    // ── Serialization ──────────────────────────────────────────────

    /// Serialize the full key pair to bytes: `[mode_tag(1) | pk | sk]`.
    ///
    /// The mode tag encodes the security level so deserialization
    /// can automatically select the correct parameters.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.pubkey.len() + self.privkey.len());
        buf.push(self.mode.mode_tag());
        buf.extend_from_slice(&self.pubkey);
        buf.extend_from_slice(&self.privkey);
        buf
    }

    /// Deserialize a key pair from the format produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(data: &[u8]) -> Result<Self, DilithiumError> {
        if data.is_empty() {
            return Err(DilithiumError::FormatError);
        }
        let mode = DilithiumMode::from_tag(data[0]).ok_or(DilithiumError::FormatError)?;
        let pk_len = mode.public_key_bytes();
        let sk_len = mode.secret_key_bytes();
        if data.len() != 1 + pk_len + sk_len {
            return Err(DilithiumError::FormatError);
        }
        let pk = &data[1..=pk_len];
        let sk = &data[1 + pk_len..];
        Self::from_keys(sk, pk, mode)
    }

    /// Export only the public key bytes with a mode tag: `[mode_tag(1) | pk]`.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.pubkey.len());
        buf.push(self.mode.mode_tag());
        buf.extend_from_slice(&self.pubkey);
        buf
    }

    /// Create a verify-only handle from tagged public key bytes.
    pub fn from_public_key(data: &[u8]) -> Result<(DilithiumMode, Vec<u8>), DilithiumError> {
        if data.is_empty() {
            return Err(DilithiumError::FormatError);
        }
        let mode = DilithiumMode::from_tag(data[0]).ok_or(DilithiumError::FormatError)?;
        if data.len() != 1 + mode.public_key_bytes() {
            return Err(DilithiumError::FormatError);
        }
        Ok((mode, data[1..].to_vec()))
    }
}

impl DilithiumSignature {
    /// Get the raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Create from raw bytes (no validation — use verify to check).
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create from a byte slice (copies).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Signature length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the signature is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Fill buffer with random bytes via `getrandom` crate (WASM compatible).
#[cfg(feature = "getrandom")]
fn getrandom(buf: &mut [u8]) -> Result<(), ()> {
    ::getrandom::getrandom(buf).map_err(|_| ())
}
