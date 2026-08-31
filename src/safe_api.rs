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

use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::packing;
pub use crate::params::DilithiumMode;
use crate::params::*;
use crate::polyvec::*;
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
/// # Security warning — `serde`
///
/// With the `serde` feature, `Serialize` emits the **raw private key in
/// plaintext**. Only serialize key pairs into encrypted or otherwise
/// protected storage, and never into logs or debug output. Prefer
/// [`public_key_bytes`](Self::public_key_bytes) when only the public half
/// is needed.
///
/// `Deserialize` runs the full [`from_keys`](Self::from_keys) validation
/// (FIPS 204 §7.1), so a deserialized key pair satisfies the same
/// invariants as one built through a constructor. That costs roughly one
/// key generation per deserialization.
///
/// Type aliases: `MlDsaKeyPair` (FIPS 204 naming) = `DilithiumKeyPair` (legacy).
///
/// # `Debug`
///
/// The `Debug` implementation deliberately **redacts the private key**; it
/// prints only the mode and the key lengths, so logging a key pair cannot
/// leak secret material.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "KeyPairRepr"))]
pub struct DilithiumKeyPair {
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_zeroizing::serialize")
    )]
    privkey: Zeroizing<Vec<u8>>,
    pubkey: Vec<u8>,
    mode: DilithiumMode,
}

impl fmt::Debug for DilithiumKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumKeyPair")
            .field("mode", &self.mode)
            .field("privkey", &"[REDACTED]")
            .field("privkey_len", &self.privkey.len())
            .field("pubkey_len", &self.pubkey.len())
            .finish()
    }
}

/// Wire representation used **only** as the `serde` deserialization target.
///
/// Deserializing straight into [`DilithiumKeyPair`] would bypass every
/// constructor check, so the derived `Deserialize` goes through this struct
/// and then [`DilithiumKeyPair::from_keys`], applying the same FIPS 204 §7.1
/// validation as [`DilithiumKeyPair::from_bytes`].
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct KeyPairRepr {
    #[serde(deserialize_with = "serde_zeroizing::deserialize")]
    privkey: Zeroizing<Vec<u8>>,
    pubkey: Vec<u8>,
    mode: DilithiumMode,
}

#[cfg(feature = "serde")]
impl TryFrom<KeyPairRepr> for DilithiumKeyPair {
    type Error = DilithiumError;

    fn try_from(repr: KeyPairRepr) -> Result<Self, Self::Error> {
        // `from_keys` copies what it needs; `repr.privkey` is zeroized when
        // it is dropped at the end of this function.
        Self::from_keys(&repr.privkey, &repr.pubkey, repr.mode)
    }
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
        Self::generate_with_rng(mode, &mut |buf| getrandom(buf))
    }

    /// Generate a key pair from a caller-supplied entropy source.
    ///
    /// `fill` must fill the whole buffer with cryptographically secure random
    /// bytes and return `Err(())` if it cannot; that becomes
    /// [`DilithiumError::RandomError`] and **no** key pair is produced. This
    /// is the entry point for `no_std` targets that have an entropy source
    /// but not `getrandom`.
    ///
    /// Dynamic dispatch (`&mut dyn FnMut`) is deliberate: it accepts stateful
    /// RNGs and keeps this function from being duplicated per closure type.
    pub fn generate_with_rng(
        mode: DilithiumMode,
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<Self, DilithiumError> {
        let mut seed = [0u8; SEEDBYTES];
        fill(&mut seed).map_err(|()| DilithiumError::RandomError)?;
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
        self.sign_with_rng(msg, ctx, &mut |buf| getrandom(buf))
    }

    /// Hedged pure ML-DSA signing with a caller-supplied entropy source.
    ///
    /// See [`generate_with_rng`](Self::generate_with_rng) for the `fill`
    /// contract. The FIPS 204 `|ctx| <= 255` limit is enforced by
    /// [`sign::sign_signature`], which reports it as
    /// [`DilithiumError::BadArgument`].
    pub fn sign_with_rng(
        &self,
        msg: &[u8],
        ctx: &[u8],
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<DilithiumSignature, DilithiumError> {
        let mut rnd = [0u8; RNDBYTES];
        fill(&mut rnd).map_err(|()| DilithiumError::RandomError)?;

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
        self.sign_prehash_with_rng(msg, ctx, &mut |buf| getrandom(buf))
    }

    /// Hedged HashML-DSA signing with a caller-supplied entropy source.
    ///
    /// See [`generate_with_rng`](Self::generate_with_rng) for the `fill`
    /// contract.
    pub fn sign_prehash_with_rng(
        &self,
        msg: &[u8],
        ctx: &[u8],
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<DilithiumSignature, DilithiumError> {
        let mut rnd = [0u8; RNDBYTES];
        fill(&mut rnd).map_err(|()| DilithiumError::RandomError)?;

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
        let mut sig = vec![0u8; self.mode.signature_bytes()];
        let ret = sign::sign_signature(self.mode, &mut sig, msg, ctx, rnd, &self.privkey);
        if ret != 0 {
            return Err(DilithiumError::BadArgument);
        }
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
    /// 2. The public key embedded in the secret key is consistent (`rho`).
    /// 3. The secret key's `tr = H(pk)` field is consistent.
    /// 4. **Full algebraic consistency**: `t = A·s1 + s2` recomputed from the
    ///    secret key matches the public key's `t1` and the secret key's `t0`.
    ///    This rejects tampered/corrupted secret keys, which could otherwise
    ///    be used to mount fault-style key-recovery attacks via signing.
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

        // Full algebraic check: recompute t = A·s1 + s2 from the secret key
        // (same computation as key generation) and verify that
        // power2round(t) reproduces both pk's t1 and sk's t0.
        let mut rho = [0u8; SEEDBYTES];
        let mut tr = [0u8; TRBYTES];
        let mut key = [0u8; SEEDBYTES];
        let mut t0 = PolyVecK::default();
        let mut s1 = PolyVecL::default();
        let mut s2 = PolyVecK::default();
        packing::unpack_sk(
            mode, &mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, privkey,
        );

        let mut mat = vec![PolyVecL::default(); K_MAX];
        matrix_expand(mode, &mut mat, &rho);
        polyvecl_ntt(mode, &mut s1);
        let mut t = PolyVecK::default();
        matrix_pointwise_montgomery(mode, &mut t, &mat, &s1);
        polyveck_reduce(mode, &mut t);
        polyveck_invntt_tomont(mode, &mut t);
        polyveck_add_assign(mode, &mut t, &s2);
        polyveck_caddq(mode, &mut t);

        let mut t1 = PolyVecK::default();
        let mut t0_expected = PolyVecK::default();
        polyveck_power2round(mode, &mut t1, &mut t0_expected, &t);

        // Repack the expected public key and compare (public data).
        let mut pk_expected = vec![0u8; mode.public_key_bytes()];
        packing::pack_pk(mode, &mut pk_expected, &rho, &t1);
        let pk_ok = pk_expected == pubkey;

        // Compare sk's t0 against the recomputed low part. `t0` is secret
        // key material, so the comparison is constant-time and never exits
        // early: it must not reveal which coefficient differs.
        let mut t0_diff = 0i32;
        for i in 0..mode.k() {
            for j in 0..N {
                t0_diff |= t0.vec[i].coeffs[j] ^ t0_expected.vec[i].coeffs[j];
            }
        }
        let t0_ok = t0_diff == 0;

        // Zeroize secret material unpacked for validation.
        key.zeroize();
        s1.zeroize();
        s2.zeroize();
        t0.zeroize();
        t0_expected.zeroize();
        t.zeroize();

        if !pk_ok || !t0_ok {
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
    ///
    /// The returned buffer contains the **plaintext private key**; it is
    /// wrapped in [`Zeroizing`] so it is wiped when dropped. It derefs to
    /// `Vec<u8>`/`[u8]`, so it can be used anywhere a byte buffer is
    /// expected — but copying it out of the wrapper defeats the wipe.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Vec::with_capacity(1 + self.pubkey.len() + self.privkey.len());
        buf.push(self.mode.mode_tag());
        buf.extend_from_slice(&self.pubkey);
        buf.extend_from_slice(&self.privkey);
        Zeroizing::new(buf)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An entropy source that always fails, to exercise the RNG-failure
    /// paths: a failing RNG must yield `RandomError` and never a key or
    /// signature (FIPS 204 §3.6.3 — no signature without fresh randomness).
    fn failing_rng(_buf: &mut [u8]) -> Result<(), ()> {
        Err(())
    }

    #[test]
    fn test_generate_reports_rng_failure() {
        let err = DilithiumKeyPair::generate_with_rng(ML_DSA_44, &mut failing_rng).unwrap_err();
        assert_eq!(err, DilithiumError::RandomError);
    }

    #[test]
    fn test_sign_reports_rng_failure() {
        let kp = DilithiumKeyPair::generate_deterministic(ML_DSA_44, &[1u8; SEEDBYTES]);
        assert_eq!(
            kp.sign_with_rng(b"m", b"", &mut failing_rng).unwrap_err(),
            DilithiumError::RandomError
        );
        assert_eq!(
            kp.sign_prehash_with_rng(b"m", b"", &mut failing_rng)
                .unwrap_err(),
            DilithiumError::RandomError
        );
    }

    /// A key pair whose private key has the wrong length cannot be built
    /// through any constructor, but it can arise from a corrupted in-memory
    /// state. Signing must then fail cleanly instead of panicking.
    #[test]
    fn test_sign_with_corrupt_private_key_returns_error() {
        let kp = DilithiumKeyPair::generate_deterministic(ML_DSA_44, &[2u8; SEEDBYTES]);
        let broken = DilithiumKeyPair {
            privkey: Zeroizing::new(kp.privkey[..kp.privkey.len() - 1].to_vec()),
            pubkey: kp.pubkey.clone(),
            mode: kp.mode,
        };

        assert_eq!(
            broken.sign_with_rng(b"m", b"", &mut |b: &mut [u8]| {
                b.fill(0);
                Ok(())
            }),
            Err(DilithiumError::BadArgument)
        );
        assert_eq!(
            broken.sign_prehash_with_rng(b"m", b"", &mut |b: &mut [u8]| {
                b.fill(0);
                Ok(())
            }),
            Err(DilithiumError::BadArgument)
        );
        assert_eq!(
            broken.sign_deterministic(b"m", b"", &[0u8; RNDBYTES]),
            Err(DilithiumError::BadArgument)
        );
    }

    /// `Debug` must never expose private key bytes.
    #[test]
    fn test_debug_redacts_private_key() {
        let kp = DilithiumKeyPair::generate_deterministic(ML_DSA_44, &[3u8; SEEDBYTES]);
        let rendered = alloc::format!("{kp:?}");
        assert!(rendered.contains("[REDACTED]"));
        // No run of actual key bytes may appear in the rendering.
        let first_bytes = alloc::format!("{:?}", &kp.privkey[..8]);
        assert!(!rendered.contains(&first_bytes));
        assert!(rendered.contains("Dilithium2"));
    }
}
