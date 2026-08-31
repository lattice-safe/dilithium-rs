//! Formal verification harnesses for [Kani](https://model-checking.github.io/kani/).
//!
//! Kani is a bounded model checker: each `#[kani::proof]` below is discharged
//! for **every** input satisfying its assumptions, by translating the Rust
//! (as compiled, including overflow and bounds checks) into SAT/SMT queries.
//! Unlike the exhaustive sweeps in `examples/exhaustive_proofs.rs`, which
//! enumerate finite domains, these are symbolic — they cover domains too
//! large to enumerate, and Kani also proves the absence of panics, integer
//! overflow and out-of-bounds accesses along the way.
//!
//! ```text
//! cargo kani --harness verification::proof_decompose_mode2
//! cargo kani            # every harness (slow)
//! ```
//!
//! Only compiled under `cfg(kani)`, so this module has no effect on normal
//! builds.

use crate::params::*;
use crate::poly::Poly;
use crate::reduce::{caddq, freeze, montgomery_reduce, reduce32};
use crate::rounding::{decompose, make_hint, power2round, use_hint};

/// `reduce32` returns a representative of the same residue class, bounded by
/// 6283008, for every input in its documented precondition.
#[kani::proof]
fn proof_reduce32_bounds() {
    let a: i32 = kani::any();
    let limit: i32 = i32::MAX - (1 << 22);
    kani::assume(a >= -limit && a <= limit);

    let r = reduce32(a);
    assert!(r.abs() <= 6_283_008);
    assert!((i64::from(r) - i64::from(a)) % i64::from(Q) == 0);
}

/// `caddq` maps every representative in `(-Q, Q)` to the canonical one.
#[kani::proof]
fn proof_caddq_canonical() {
    let a: i32 = kani::any();
    kani::assume(a > -Q && a < Q);

    let r = caddq(a);
    assert!(r >= 0 && r < Q);
    assert!(r == a || r == a + Q);
}

/// `freeze` is total on `reduce32`'s output range and lands in `[0, Q)`.
#[kani::proof]
fn proof_freeze_canonical() {
    let a: i32 = kani::any();
    let limit: i32 = i32::MAX - (1 << 22);
    kani::assume(a >= -limit && a <= limit);

    let r = freeze(a);
    assert!(r >= 0 && r < Q);
    assert!((i64::from(r) - i64::from(a)) % i64::from(Q) == 0);
}

/// Montgomery reduction: `r · 2^32 ≡ a (mod Q)` with `|r| < Q`, for every
/// product the NTT and the pointwise multiplications can form.
///
/// The congruence is stated as an exact identity with the witness `t` that
/// the implementation computes, `r · 2^32 = a − t·Q`, rather than as
/// `(r·2^32 − a) mod Q == 0`. The two are equivalent (`t·Q ≡ 0 mod Q`), but
/// the identity form needs no symbolic division, which a bit-vector solver
/// handles orders of magnitude faster.
/// `|montgomery_reduce(a)| < Q` for every product the transform can form.
///
/// The input is modelled as the product the callers actually build — a
/// twiddle factor times a coefficient — rather than an unconstrained `i64`:
/// two symbolic 32-bit factors are much cheaper for a bit-vector solver than
/// one symbolic 64-bit value, and `|zeta| < Q`, `|coeff| < 9Q` (the widest
/// point of the NTT) is exactly the range the implementation must handle.
#[kani::proof]
fn proof_montgomery_reduce_bound() {
    let zeta: i32 = kani::any();
    let coeff: i32 = kani::any();
    kani::assume(zeta > -Q && zeta < Q);
    kani::assume(coeff > -9 * Q && coeff < 9 * Q);

    let a = i64::from(zeta) * i64::from(coeff);
    let r = montgomery_reduce(a);

    assert!(i64::from(r) > -i64::from(Q) && i64::from(r) < i64::from(Q));
}

/// `r · 2^32 = a − t·Q`, i.e. `r ≡ a·2^{-32} (mod Q)`.
///
/// Not part of the default run: the property rests on
/// `Q · QINV ≡ 1 (mod 2^32)` zeroing the low 32 bits of `a − t·Q`, and
/// bit-blasting a 32-bit multiplicative inverse does not converge in
/// reasonable time (CBMC was still running after five minutes). Excluded in
/// CI via `--exclude-harness`; the congruence is instead verified over the
/// NTT-reachable products by `examples/exhaustive_proofs.rs` and by the
/// bit-exact model in `scripts/algebra_check.py`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_montgomery_reduce_congruence() {
    let zeta: i32 = kani::any();
    let coeff: i32 = kani::any();
    kani::assume(zeta > -Q && zeta < Q);
    kani::assume(coeff > -9 * Q && coeff < 9 * Q);

    let a = i64::from(zeta) * i64::from(coeff);
    let t = (a as i32).wrapping_mul(QINV as i32);
    let r = montgomery_reduce(a);

    assert!(i64::from(r) * 4_294_967_296 == a - i64::from(t) * i64::from(Q));
}

/// FIPS 204 Algorithm 35: `a = a1·2^d + a0` with `a0 ∈ (−2^{d−1}, 2^{d−1}]`.
#[kani::proof]
fn proof_power2round() {
    let a: i32 = kani::any();
    kani::assume(a >= 0 && a < Q);

    let (a1, a0) = power2round(a);
    assert!(a0 > -(1 << (D - 1)) && a0 <= (1 << (D - 1)));
    assert!(a1 >= 0 && a1 < 1024);
    assert!(a1 * (1 << D) + a0 == a);
}

fn decompose_contract(mode: DilithiumMode) {
    let a: i32 = kani::any();
    kani::assume(a >= 0 && a < Q);

    let gamma2 = mode.gamma2();
    let m = (Q - 1) / (2 * gamma2);
    let (a1, a0) = decompose(mode, a);

    assert!(a1 >= 0 && a1 < m);
    assert!(a0.abs() <= gamma2);
    // a ≡ a1·2γ₂ + a0 (mod Q)
    let recomposed = i64::from(a1) * 2 * i64::from(gamma2) + i64::from(a0);
    assert!((recomposed - i64::from(a)) % i64::from(Q) == 0);
}

/// FIPS 204 Algorithm 36 for γ₂ = (Q−1)/88.
#[kani::proof]
fn proof_decompose_mode2() {
    decompose_contract(DilithiumMode::Dilithium2);
}

/// FIPS 204 Algorithm 36 for γ₂ = (Q−1)/32.
#[kani::proof]
fn proof_decompose_mode3() {
    decompose_contract(DilithiumMode::Dilithium3);
}

/// The branchless `make_hint` has exactly the reference truth table, for
/// every `(a0, a1)` — including the `a0 == −γ₂` boundary.
#[kani::proof]
fn proof_make_hint_matches_reference() {
    let a0: i32 = kani::any();
    let a1: i32 = kani::any();
    // a0 is a coefficient of w0 after reduce32; a1 is a high-bits value.
    // Written as explicit bounds rather than `a0.abs() <= ...`, which would
    // itself overflow for a0 == i32::MIN before the assumption applies.
    kani::assume(a0 >= -6_283_008 && a0 <= 6_283_008);
    kani::assume(a1 >= 0 && a1 <= 44);

    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let gamma2 = mode.gamma2();
        let reference = a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0);
        assert_eq!(make_hint(mode, a0, a1), reference);
    }
}

/// `use_hint` always returns a valid high-bits value, for every field
/// element and either hint bit.
#[kani::proof]
fn proof_use_hint_range() {
    let a: i32 = kani::any();
    let hint: bool = kani::any();
    kani::assume(a >= 0 && a < Q);

    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let m = (Q - 1) / (2 * mode.gamma2());
        let out = use_hint(mode, a, hint);
        assert!(out >= 0 && out < m);
    }
}

/// The branchless `chknorm` computes the mathematical predicate
/// `max|coeff| >= bound` without overflow.
///
/// Scope: the first eight coefficients are symbolic and the rest are zero.
/// The full 256-iteration loop still runs, so this covers the accumulation
/// and the absolute-value computation, but it is a restricted input family,
/// not the whole `[i32; 256]` domain (which is out of reach for a bit-vector
/// solver). The scalar predicate itself is verified over its complete domain
/// by `examples/exhaustive_proofs.rs`.
#[kani::proof]
fn proof_chknorm_matches_definition() {
    let bound: i32 = kani::any();
    kani::assume(bound > 0 && bound <= (Q - 1) / 8);

    let mut p = Poly::zero();
    let mut expected = false;
    for i in 0..8 {
        let c: i32 = kani::any();
        kani::assume(c >= -6_283_008 && c <= 6_283_008);
        p.coeffs[i] = c;
        if c >= bound || c <= -bound {
            expected = true;
        }
    }

    assert_eq!(p.chknorm(bound), expected);
}

/// `polyt1_unpack` must confine every output coefficient to 10 bits for
/// *arbitrary* input bytes: `t1` comes straight from an attacker-supplied
/// public key, and the shift by `D` later must not overflow.
#[kani::proof]
fn proof_polyt1_unpack_range() {
    let bytes: [u8; POLYT1_PACKEDBYTES] = kani::any();
    let mut p = Poly::zero();
    Poly::polyt1_unpack(&mut p, &bytes);

    for i in 0..N {
        assert!(p.coeffs[i] >= 0 && p.coeffs[i] < 1024);
    }
    // The verifier shifts t1 left by D; that must stay in range.
    assert!((1023i32 << D) < i32::MAX);
}

/// `polyeta_unpack` on arbitrary bytes yields coefficients within the range
/// the arithmetic assumes, so a tampered secret key cannot push `s1`/`s2`
/// out of bounds.
#[kani::proof]
fn proof_polyeta_unpack_range() {
    let mode = DilithiumMode::Dilithium2; // eta = 2, 3-bit fields
    let bytes: [u8; 96] = kani::any();
    let mut p = Poly::zero();
    Poly::polyeta_unpack(mode, &mut p, &bytes);

    let eta = mode.eta();
    for i in 0..N {
        // 3-bit field subtracted from eta: [eta-7, eta]
        assert!(p.coeffs[i] <= eta && p.coeffs[i] >= eta - 7);
    }
}

/// `polyz_unpack` on arbitrary bytes stays inside the range that keeps the
/// subsequent `reduce32` and NTT within their preconditions.
#[kani::proof]
fn proof_polyz_unpack_range() {
    let mode = DilithiumMode::Dilithium2; // gamma1 = 2^17, 18-bit fields
    let bytes: [u8; 576] = kani::any();
    let mut p = Poly::zero();
    Poly::polyz_unpack(mode, &mut p, &bytes);

    let gamma1 = mode.gamma1();
    for i in 0..N {
        assert!(p.coeffs[i] <= gamma1 && p.coeffs[i] >= gamma1 - 0x3FFFF);
    }
}
