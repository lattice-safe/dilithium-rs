//! Dilithium parameter sets (FIPS 204 / ML-DSA).
//!
//! Three security levels are supported:
//! - ML-DSA-44 (Dilithium2, NIST Level 2)
//! - ML-DSA-65 (Dilithium3, NIST Level 3)
//! - ML-DSA-87 (Dilithium5, NIST Level 5)

/// Polynomial ring degree.
pub const N: usize = 256;

/// Modulus.
pub const Q: i32 = 8380417;

/// Montgomery constant: Q^{-1} mod 2^32.
pub const QINV: i64 = 58728449; // Q * QINV ≡ 1 (mod 2^32)

/// Number of dropped bits from t.
pub const D: u32 = 13;

/// Root of unity (used in NTT).
pub const ROOT_OF_UNITY: i32 = 1753;

/// Seed length in bytes.
pub const SEEDBYTES: usize = 32;

/// CRH output length in bytes.
pub const CRHBYTES: usize = 64;

/// tr length in bytes.
pub const TRBYTES: usize = 64;

/// Random bytes for hedged signing.
pub const RNDBYTES: usize = 32;

/// Maximum K across all modes (Mode5: K=8).
pub const K_MAX: usize = 8;

/// Maximum L across all modes (Mode5: L=7).
pub const L_MAX: usize = 7;

/// Packed size for t1 polynomial (10 bits per coefficient).
pub const POLYT1_PACKEDBYTES: usize = 320;

/// Packed size for t0 polynomial (13 bits per coefficient).
pub const POLYT0_PACKEDBYTES: usize = 416;

/// ML-DSA / Dilithium security levels (FIPS 204).
///
/// The FIPS 204 standard names are ML-DSA-44, ML-DSA-65, and ML-DSA-87.
/// The Dilithium2/3/5 names are provided for compatibility with the
/// original CRYSTALS-Dilithium submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DilithiumMode {
    /// ML-DSA-44 (NIST Level 2): K=4, L=4
    Dilithium2,
    /// ML-DSA-65 (NIST Level 3): K=6, L=5
    Dilithium3,
    /// ML-DSA-87 (NIST Level 5): K=8, L=7
    Dilithium5,
}

/// FIPS 204 type alias: ML-DSA-44 ≡ Dilithium2.
pub const ML_DSA_44: DilithiumMode = DilithiumMode::Dilithium2;
/// FIPS 204 type alias: ML-DSA-65 ≡ Dilithium3.
pub const ML_DSA_65: DilithiumMode = DilithiumMode::Dilithium3;
/// FIPS 204 type alias: ML-DSA-87 ≡ Dilithium5.
pub const ML_DSA_87: DilithiumMode = DilithiumMode::Dilithium5;

/// OID for id-HashML-DSA-44-with-SHA512 (FIPS 204 §6.2).
pub const HASH_ML_DSA_44_OID: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
/// OID for id-HashML-DSA-65-with-SHA512 (FIPS 204 §6.2).
pub const HASH_ML_DSA_65_OID: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];
/// OID for id-HashML-DSA-87-with-SHA512 (FIPS 204 §6.2).
pub const HASH_ML_DSA_87_OID: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];

impl DilithiumMode {
    /// Byte tag for binary serialization (matches NIST level: 2, 3, 5).
    #[inline]
    #[must_use]
    pub const fn mode_tag(self) -> u8 {
        match self {
            Self::Dilithium2 => 0x02,
            Self::Dilithium3 => 0x03,
            Self::Dilithium5 => 0x05,
        }
    }

    /// Recover mode from a serialization tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x02 => Some(Self::Dilithium2),
            0x03 => Some(Self::Dilithium3),
            0x05 => Some(Self::Dilithium5),
            _ => None,
        }
    }

    /// Number of rows in the matrix A.
    #[inline]
    #[must_use]
    pub const fn k(self) -> usize {
        match self {
            Self::Dilithium2 => 4,
            Self::Dilithium3 => 6,
            Self::Dilithium5 => 8,
        }
    }

    /// Number of columns in the matrix A.
    #[inline]
    #[must_use]
    pub const fn l(self) -> usize {
        match self {
            Self::Dilithium2 => 4,
            Self::Dilithium3 => 5,
            Self::Dilithium5 => 7,
        }
    }

    /// Secret key coefficient bound.
    #[inline]
    #[must_use]
    pub const fn eta(self) -> i32 {
        match self {
            Self::Dilithium2 => 2,
            Self::Dilithium3 => 4,
            Self::Dilithium5 => 2,
        }
    }

    /// Number of ±1 coefficients in the challenge polynomial.
    #[inline]
    #[must_use]
    pub const fn tau(self) -> usize {
        match self {
            Self::Dilithium2 => 39,
            Self::Dilithium3 => 49,
            Self::Dilithium5 => 60,
        }
    }

    /// Rejection bound: TAU * ETA.
    #[inline]
    #[must_use]
    pub const fn beta(self) -> i32 {
        match self {
            Self::Dilithium2 => 78,
            Self::Dilithium3 => 196,
            Self::Dilithium5 => 120,
        }
    }

    /// Masking vector coefficient range: coefficients in [-(GAMMA1-1), GAMMA1].
    #[inline]
    #[must_use]
    pub const fn gamma1(self) -> i32 {
        match self {
            Self::Dilithium2 => 1 << 17, // 131072
            Self::Dilithium3 => 1 << 19, // 524288
            Self::Dilithium5 => 1 << 19,
        }
    }

    /// Low-order rounding range: GAMMA2 = (Q-1)/88 or (Q-1)/32.
    #[inline]
    #[must_use]
    pub const fn gamma2(self) -> i32 {
        match self {
            Self::Dilithium2 => (Q - 1) / 88, // 95232
            Self::Dilithium3 => (Q - 1) / 32, // 261888
            Self::Dilithium5 => (Q - 1) / 32,
        }
    }

    /// Maximum number of ones in the hint vector.
    #[inline]
    #[must_use]
    pub const fn omega(self) -> usize {
        match self {
            Self::Dilithium2 => 80,
            Self::Dilithium3 => 55,
            Self::Dilithium5 => 75,
        }
    }

    /// Challenge hash output length in bytes.
    #[inline]
    #[must_use]
    pub const fn ctildebytes(self) -> usize {
        match self {
            Self::Dilithium2 => 32,
            Self::Dilithium3 => 48,
            Self::Dilithium5 => 64,
        }
    }

    /// Packed size for z polynomial.
    #[inline]
    #[must_use]
    pub const fn polyz_packedbytes(self) -> usize {
        match self {
            Self::Dilithium2 => 576, // gamma1 = 2^17
            Self::Dilithium3 => 640, // gamma1 = 2^19
            Self::Dilithium5 => 640,
        }
    }

    /// Packed size for w1 polynomial.
    #[inline]
    #[must_use]
    pub const fn polyw1_packedbytes(self) -> usize {
        match self {
            Self::Dilithium2 => 192, // gamma2 = (Q-1)/88
            Self::Dilithium3 => 128, // gamma2 = (Q-1)/32
            Self::Dilithium5 => 128,
        }
    }

    /// Packed size for eta polynomial.
    #[inline]
    #[must_use]
    pub const fn polyeta_packedbytes(self) -> usize {
        match self {
            Self::Dilithium2 => 96,  // eta = 2
            Self::Dilithium3 => 128, // eta = 4
            Self::Dilithium5 => 96,
        }
    }

    /// Public key size in bytes.
    #[inline]
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        SEEDBYTES + self.k() * POLYT1_PACKEDBYTES
    }

    /// Secret key size in bytes.
    #[inline]
    #[must_use]
    pub const fn secret_key_bytes(self) -> usize {
        2 * SEEDBYTES
            + TRBYTES
            + self.l() * self.polyeta_packedbytes()
            + self.k() * self.polyeta_packedbytes()
            + self.k() * POLYT0_PACKEDBYTES
    }

    /// Signature size in bytes.
    #[inline]
    #[must_use]
    pub const fn signature_bytes(self) -> usize {
        self.ctildebytes() + self.l() * self.polyz_packedbytes() + self.omega() + self.k()
    }

    /// Get the HashML-DSA OID for this mode.
    #[inline]
    #[must_use]
    pub fn hash_oid(self) -> &'static [u8] {
        match self {
            Self::Dilithium2 => HASH_ML_DSA_44_OID,
            Self::Dilithium3 => HASH_ML_DSA_65_OID,
            Self::Dilithium5 => HASH_ML_DSA_87_OID,
        }
    }

    /// FIPS 204 algorithm name.
    #[must_use]
    pub fn fips_name(self) -> &'static str {
        match self {
            Self::Dilithium2 => "ML-DSA-44",
            Self::Dilithium3 => "ML-DSA-65",
            Self::Dilithium5 => "ML-DSA-87",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium2_sizes() {
        let m = DilithiumMode::Dilithium2;
        assert_eq!(m.public_key_bytes(), 1312);
        assert_eq!(m.secret_key_bytes(), 2560);
        assert_eq!(m.signature_bytes(), 2420);
    }

    #[test]
    fn test_dilithium3_sizes() {
        let m = DilithiumMode::Dilithium3;
        assert_eq!(m.public_key_bytes(), 1952);
        assert_eq!(m.secret_key_bytes(), 4032);
        assert_eq!(m.signature_bytes(), 3309);
    }

    #[test]
    fn test_dilithium5_sizes() {
        let m = DilithiumMode::Dilithium5;
        assert_eq!(m.public_key_bytes(), 2592);
        assert_eq!(m.secret_key_bytes(), 4896);
        assert_eq!(m.signature_bytes(), 4627);
    }
}
