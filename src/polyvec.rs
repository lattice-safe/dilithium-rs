//! Polynomial vector operations for Dilithium.
//!
//! Faithful port of `polyvec.c` from the CRYSTALS-Dilithium reference.
//! Two types: `PolyVecL` (length L) and `PolyVecK` (length K), using
//! max-size arrays with runtime dimension from `DilithiumMode`.

use crate::params::*;
use crate::poly::Poly;

/// Vector of polynomials of length L (max L=7 for Mode5).
#[derive(Clone)]
pub struct PolyVecL {
    pub vec: [Poly; L_MAX],
}

impl Default for PolyVecL {
    fn default() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::zero()),
        }
    }
}

/// Vector of polynomials of length K (max K=8 for Mode5).
#[derive(Clone)]
pub struct PolyVecK {
    pub vec: [Poly; K_MAX],
}

impl Default for PolyVecK {
    fn default() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::zero()),
        }
    }
}

// ================================================================
// Matrix expansion
// ================================================================

/// Expand matrix A from seed rho. Matrix is K x L of polynomials.
pub fn matrix_expand(mode: DilithiumMode, mat: &mut [PolyVecL], rho: &[u8; SEEDBYTES]) {
    let k = mode.k();
    let l = mode.l();
    for i in 0..k {
        for j in 0..l {
            Poly::uniform(&mut mat[i].vec[j], rho, ((i << 8) + j) as u16);
        }
    }
}

/// Matrix-vector multiplication: t = A * v (in NTT domain).
pub fn matrix_pointwise_montgomery(
    mode: DilithiumMode,
    t: &mut PolyVecK,
    mat: &[PolyVecL],
    v: &PolyVecL,
) {
    let k = mode.k();
    for i in 0..k {
        polyvecl_pointwise_acc_montgomery(mode, &mut t.vec[i], &mat[i], v);
    }
}

// ================================================================
// PolyVecL operations
// ================================================================

/// Sample short vector with eta-bounded coefficients.
pub fn polyvecl_uniform_eta(
    mode: DilithiumMode,
    v: &mut PolyVecL,
    seed: &[u8; CRHBYTES],
    nonce: u16,
) {
    let l = mode.l();
    for i in 0..l {
        Poly::uniform_eta(mode, &mut v.vec[i], seed, nonce + i as u16);
    }
}

/// Sample masking vector with gamma1-bounded coefficients.
pub fn polyvecl_uniform_gamma1(
    mode: DilithiumMode,
    v: &mut PolyVecL,
    seed: &[u8; CRHBYTES],
    nonce: u16,
) {
    let l = mode.l();
    for i in 0..l {
        Poly::uniform_gamma1(mode, &mut v.vec[i], seed, nonce + i as u16);
    }
}

/// Reduce all coefficients of polynomials in vector.
pub fn polyvecl_reduce(mode: DilithiumMode, v: &mut PolyVecL) {
    for i in 0..mode.l() {
        v.vec[i].reduce();
    }
}

/// Add vectors of polynomials: w = u + v.
pub fn polyvecl_add(mode: DilithiumMode, w: &mut PolyVecL, u: &PolyVecL, v: &PolyVecL) {
    for i in 0..mode.l() {
        Poly::add(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/// Forward NTT of all polynomials in vector.
pub fn polyvecl_ntt(mode: DilithiumMode, v: &mut PolyVecL) {
    for i in 0..mode.l() {
        v.vec[i].ntt();
    }
}

/// Inverse NTT of all polynomials in vector.
pub fn polyvecl_invntt_tomont(mode: DilithiumMode, v: &mut PolyVecL) {
    for i in 0..mode.l() {
        v.vec[i].invntt_tomont();
    }
}

/// Pointwise multiply all polynomials in vector by scalar polynomial.
pub fn polyvecl_pointwise_poly_montgomery(
    mode: DilithiumMode,
    r: &mut PolyVecL,
    a: &Poly,
    v: &PolyVecL,
) {
    for i in 0..mode.l() {
        Poly::pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
    }
}

/// Pointwise multiply two vectors and accumulate.
pub fn polyvecl_pointwise_acc_montgomery(
    mode: DilithiumMode,
    w: &mut Poly,
    u: &PolyVecL,
    v: &PolyVecL,
) {
    let l = mode.l();
    let mut t = Poly::zero();
    Poly::pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
    for i in 1..l {
        Poly::pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
        let w_copy = w.clone();
        Poly::add(w, &w_copy, &t);
    }
}

/// Check infinity norm of polynomials in vector.
/// Returns `true` if any polynomial has norm >= bound.
#[must_use]
pub fn polyvecl_chknorm(mode: DilithiumMode, v: &PolyVecL, bound: i32) -> bool {
    for i in 0..mode.l() {
        if v.vec[i].chknorm(bound) {
            return true;
        }
    }
    false
}

// ================================================================
// PolyVecK operations
// ================================================================

/// Sample short vector with eta-bounded coefficients.
pub fn polyveck_uniform_eta(
    mode: DilithiumMode,
    v: &mut PolyVecK,
    seed: &[u8; CRHBYTES],
    nonce: u16,
) {
    let k = mode.k();
    for i in 0..k {
        Poly::uniform_eta(mode, &mut v.vec[i], seed, nonce + i as u16);
    }
}

/// Reduce all coefficients.
pub fn polyveck_reduce(mode: DilithiumMode, v: &mut PolyVecK) {
    for i in 0..mode.k() {
        v.vec[i].reduce();
    }
}

/// Add Q if negative.
pub fn polyveck_caddq(mode: DilithiumMode, v: &mut PolyVecK) {
    for i in 0..mode.k() {
        v.vec[i].caddq();
    }
}

/// Add vectors: w = u + v.
pub fn polyveck_add(mode: DilithiumMode, w: &mut PolyVecK, u: &PolyVecK, v: &PolyVecK) {
    for i in 0..mode.k() {
        Poly::add(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/// Subtract vectors: w = u - v.
pub fn polyveck_sub(mode: DilithiumMode, w: &mut PolyVecK, u: &PolyVecK, v: &PolyVecK) {
    for i in 0..mode.k() {
        Poly::sub(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/// Shift left by D.
pub fn polyveck_shiftl(mode: DilithiumMode, v: &mut PolyVecK) {
    for i in 0..mode.k() {
        v.vec[i].shiftl();
    }
}

/// Forward NTT.
pub fn polyveck_ntt(mode: DilithiumMode, v: &mut PolyVecK) {
    for i in 0..mode.k() {
        v.vec[i].ntt();
    }
}

/// Inverse NTT.
pub fn polyveck_invntt_tomont(mode: DilithiumMode, v: &mut PolyVecK) {
    for i in 0..mode.k() {
        v.vec[i].invntt_tomont();
    }
}

/// Pointwise multiply vector by scalar polynomial.
pub fn polyveck_pointwise_poly_montgomery(
    mode: DilithiumMode,
    r: &mut PolyVecK,
    a: &Poly,
    v: &PolyVecK,
) {
    for i in 0..mode.k() {
        Poly::pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
    }
}

/// Power-of-2 rounding of all polynomials.
pub fn polyveck_power2round(
    mode: DilithiumMode,
    v1: &mut PolyVecK,
    v0: &mut PolyVecK,
    v: &PolyVecK,
) {
    for i in 0..mode.k() {
        Poly::power2round(&mut v1.vec[i], &mut v0.vec[i], &v.vec[i]);
    }
}

/// Decompose all polynomials.
pub fn polyveck_decompose(mode: DilithiumMode, v1: &mut PolyVecK, v0: &mut PolyVecK, v: &PolyVecK) {
    for i in 0..mode.k() {
        Poly::decompose(mode, &mut v1.vec[i], &mut v0.vec[i], &v.vec[i]);
    }
}

/// Make hint for all polynomials. Returns number of ones.
pub fn polyveck_make_hint(
    mode: DilithiumMode,
    h: &mut PolyVecK,
    v0: &PolyVecK,
    v1: &PolyVecK,
) -> usize {
    let mut s = 0;
    for i in 0..mode.k() {
        s += Poly::make_hint(mode, &mut h.vec[i], &v0.vec[i], &v1.vec[i]);
    }
    s
}

/// Use hint for all polynomials.
pub fn polyveck_use_hint(mode: DilithiumMode, w: &mut PolyVecK, v: &PolyVecK, h: &PolyVecK) {
    for i in 0..mode.k() {
        Poly::use_hint(mode, &mut w.vec[i], &v.vec[i], &h.vec[i]);
    }
}

/// Pack w1 polynomials.
pub fn polyveck_pack_w1(mode: DilithiumMode, r: &mut [u8], w1: &PolyVecK) {
    let packed = mode.polyw1_packedbytes();
    for i in 0..mode.k() {
        Poly::polyw1_pack(mode, &mut r[i * packed..(i + 1) * packed], &w1.vec[i]);
    }
}

/// Check infinity norm of polynomials in vector.
#[must_use]
pub fn polyveck_chknorm(mode: DilithiumMode, v: &PolyVecK, bound: i32) -> bool {
    for i in 0..mode.k() {
        if v.vec[i].chknorm(bound) {
            return true;
        }
    }
    false
}
