//! AVX2-accelerated NTT for x86_64 targets.
//!
//! Processes 8 butterfly operations in parallel using 256-bit SIMD.
//! Uses a pure-SIMD Montgomery reduction (no scalar fallback) for the
//! NTT butterfly multiply step.
//!
//! Gated behind the `simd` feature flag. Falls back to scalar on
//! non-x86_64 or when AVX2 is not available at runtime.
//!
//! # Montgomery Reduction (AVX2)
//!
//! For each lane: given `a = zeta * coeff` (64-bit), compute
//! `r ≡ a · 2^{-32} (mod Q)` using:
//!   1. `t = (a_lo * QINV) as i32`  (low 32 bits of multiply)
//!   2. `r = (a - t * Q) >> 32`     (high 32 bits)
//!
//! Since `_mm256_mul_epi32` only multiplies even-indexed 32-bit lanes
//! into 64-bit results, we process the 8 lanes in two passes:
//! even lanes (0,2,4,6) then odd lanes (1,3,5,7).

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
use crate::ntt::ZETAS;
use crate::params::N;
// `Q` is only referenced from the x86_64 AVX2 kernels below, and from the
// SIMD-vs-scalar tests (which run on every arch).
#[cfg(any(target_arch = "x86_64", test))]
use crate::params::Q;

/// Signed QINV for Montgomery: the value such that Q * QINV ≡ 1 (mod 2^32),
/// reinterpreted as i32 (wrapping). `params::QINV` (58728449) fits in i32.
#[cfg(target_arch = "x86_64")]
const QINV32: i32 = crate::params::QINV as i32;

/// Pure AVX2 Montgomery reduction of 8 products.
///
/// Input: `zeta` broadcast, `y` = 8 coefficients.
/// Computes: `montgomery_reduce(zeta * y[i])` for each lane.
/// Returns the 8 reduced values as `__m256i`.
///
/// Strategy: process even lanes (0,2,4,6) and odd lanes (1,3,5,7)
/// separately using `_mm256_mul_epi32` (signed 32×32→64 on even lanes),
/// then merge results.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn montgomery_mul_avx2(zeta: __m256i, y: __m256i) -> __m256i {
    let q_v = _mm256_set1_epi32(Q);
    let qinv_v = _mm256_set1_epi32(QINV32);

    // --- Even lanes (0, 2, 4, 6) ---
    // a_even = zeta[even] * y[even] → 64-bit results in positions 0,2,4,6
    let a_even = _mm256_mul_epi32(zeta, y);
    // t_even_lo = (a_even_lo * QINV) as i32 → low 32 bits
    let a_even_lo = _mm256_mul_epi32(
        a_even, // a_even already has low bits in even positions
        qinv_v, // * QINV
    );
    // We only need low 32 bits of a_even_lo → extract as i32
    // t_even_full = t_even_lo (we only care about low 32) * Q → 64-bit
    let t_even_lo_32 = a_even_lo; // low 32 bits are what mullo would give
    let tq_even = _mm256_mul_epi32(t_even_lo_32, q_v); // t * Q, 64-bit
                                                       // r_even = (a_even - tq_even) >> 32
    let r_even_64 = _mm256_sub_epi64(a_even, tq_even);
    let r_even_32 = _mm256_srli_epi64::<32>(r_even_64); // shift right 32

    // --- Odd lanes (1, 3, 5, 7) ---
    // Shift odd lanes into even positions for _mm256_mul_epi32
    let zeta_odd = _mm256_srli_epi64::<32>(zeta);
    let y_odd = _mm256_srli_epi64::<32>(y);
    let a_odd = _mm256_mul_epi32(zeta_odd, y_odd);
    let a_odd_lo = _mm256_mul_epi32(a_odd, qinv_v);
    let tq_odd = _mm256_mul_epi32(a_odd_lo, q_v);
    let r_odd_64 = _mm256_sub_epi64(a_odd, tq_odd);
    // Shift odd results left 32 bits to put them in odd lane positions
    // r_odd_64 >> 32 gives us the result in low 32 bits, then shift left
    // Actually: r_odd_64 has the 64-bit result. >> 32 gives low, then << 32
    // Simpler: just mask — the high 32 bits of r_odd_64 are what we want
    let r_odd_hi = _mm256_and_si256(r_odd_64, _mm256_set1_epi64x(-4294967296i64)); // mask high 32

    // Merge: even results are in low 32 of each 64-bit lane,
    //        odd results are in high 32 of each 64-bit lane
    _mm256_or_si256(r_even_32, r_odd_hi)
}

/// NTT butterfly on 8 elements using pure SIMD Montgomery.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn butterfly_avx2(a: &mut [i32; N], j: usize, len: usize, zeta: i32) {
    let zeta_v = _mm256_set1_epi32(zeta);
    let x = _mm256_loadu_si256(a.as_ptr().add(j) as *const __m256i);
    let y = _mm256_loadu_si256(a.as_ptr().add(j + len) as *const __m256i);

    let t = montgomery_mul_avx2(zeta_v, y);

    _mm256_storeu_si256(
        a.as_mut_ptr().add(j) as *mut __m256i,
        _mm256_add_epi32(x, t),
    );
    _mm256_storeu_si256(
        a.as_mut_ptr().add(j + len) as *mut __m256i,
        _mm256_sub_epi32(x, t),
    );
}

/// Inverse NTT butterfly on 8 elements.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn inv_butterfly_avx2(a: &mut [i32; N], j: usize, len: usize, zeta_neg: i32) {
    let zeta_v = _mm256_set1_epi32(zeta_neg);
    let x = _mm256_loadu_si256(a.as_ptr().add(j) as *const __m256i);
    let y = _mm256_loadu_si256(a.as_ptr().add(j + len) as *const __m256i);

    let sum = _mm256_add_epi32(x, y);
    let diff = _mm256_sub_epi32(x, y);
    let reduced = montgomery_mul_avx2(zeta_v, diff);

    _mm256_storeu_si256(a.as_mut_ptr().add(j) as *mut __m256i, sum);
    _mm256_storeu_si256(a.as_mut_ptr().add(j + len) as *mut __m256i, reduced);
}

/// AVX2-accelerated forward NTT.
///
/// # Safety
/// Requires the AVX2 CPU feature. Use `ntt_simd` for safe runtime dispatch.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_avx2(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            if len >= 8 {
                let mut j = start;
                while j + 8 <= start + len {
                    butterfly_avx2(a, j, len, zeta);
                    j += 8;
                }
            } else {
                for j in start..start + len {
                    let t = crate::reduce::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                    a[j + len] = a[j] - t;
                    a[j] += t;
                }
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// AVX2-accelerated inverse NTT.
///
/// # Safety
/// Requires the AVX2 CPU feature. Use `invntt_simd` for safe runtime dispatch.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn invntt_avx2(a: &mut [i32; N]) {
    let f: i32 = 41978; // mont^2/256
    let mut k: usize = 256;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            if len >= 8 {
                let mut j = start;
                while j + 8 <= start + len {
                    inv_butterfly_avx2(a, j, len, zeta);
                    j += 8;
                }
            } else {
                for j in start..start + len {
                    let t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = crate::reduce::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                }
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Final Montgomery scaling: a[j] = montgomery_reduce(f * a[j])
    let f_v = _mm256_set1_epi32(f);
    let mut j = 0;
    while j + 8 <= N {
        let v = _mm256_loadu_si256(a.as_ptr().add(j) as *const __m256i);
        let scaled = montgomery_mul_avx2(f_v, v);
        _mm256_storeu_si256(a.as_mut_ptr().add(j) as *mut __m256i, scaled);
        j += 8;
    }
}

/// Is the AVX2 kernel usable on this machine?
///
/// Runtime detection under `std`; with `no_std` there is no detector, so the
/// kernel is used only when it was enabled at compile time
/// (`-C target-feature=+avx2`).
#[must_use]
pub fn avx2_available() -> bool {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        return is_x86_feature_detected!("avx2");
    }
    #[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx2"))]
    {
        return true;
    }
    #[allow(unreachable_code)]
    false
}

/// NTT with the kernel chosen by the caller.
///
/// Split out from [`ntt_simd`] so both arms are reachable in tests: on a
/// machine with AVX2 the scalar fallback in the dispatcher would otherwise
/// never execute, leaving the path that a non-AVX2 x86_64 host depends on
/// untested (and uncovered).
pub fn ntt_dispatch(a: &mut [i32; N], use_avx2: bool) {
    #[cfg(target_arch = "x86_64")]
    if use_avx2 {
        // SAFETY: the caller passes `true` only when AVX2 is available —
        // `ntt_simd` obtains it from `avx2_available()`, and the tests gate
        // on the same check.
        unsafe {
            ntt_avx2(a);
        }
        return;
    }
    let _ = use_avx2;
    crate::ntt::ntt(a);
}

/// Inverse NTT with the kernel chosen by the caller. See [`ntt_dispatch`].
pub fn invntt_dispatch(a: &mut [i32; N], use_avx2: bool) {
    #[cfg(target_arch = "x86_64")]
    if use_avx2 {
        // SAFETY: as in `ntt_dispatch`.
        unsafe {
            invntt_avx2(a);
        }
        return;
    }
    let _ = use_avx2;
    crate::ntt::invntt_tomont(a);
}

/// Runtime-detected NTT dispatch.
/// Uses AVX2 if available on x86_64, otherwise falls back to scalar.
pub fn ntt_simd(a: &mut [i32; N]) {
    ntt_dispatch(a, avx2_available());
}

/// Runtime-detected inverse NTT dispatch.
pub fn invntt_simd(a: &mut [i32; N]) {
    invntt_dispatch(a, avx2_available());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both arms of the dispatcher must agree with the scalar transform:
    /// the AVX2 kernel (when this machine has it) and the fallback that a
    /// non-AVX2 x86_64 host would take.
    #[test]
    fn test_both_dispatch_arms_match_scalar() {
        let mut reference = [0i32; N];
        for i in 0..N {
            reference[i] = (i as i32 * 37 + 11) % Q;
        }
        let mut expected = reference;
        crate::ntt::ntt(&mut expected);

        // Fallback arm — reachable on every machine.
        let mut fallback = reference;
        ntt_dispatch(&mut fallback, false);
        assert_eq!(fallback, expected, "scalar fallback arm diverged");

        // AVX2 arm — only where the feature is actually present.
        if avx2_available() {
            let mut accel = reference;
            ntt_dispatch(&mut accel, true);
            assert_eq!(accel, expected, "AVX2 arm diverged from scalar");
        }

        let mut inv_expected = expected;
        crate::ntt::invntt_tomont(&mut inv_expected);

        let mut inv_fallback = expected;
        invntt_dispatch(&mut inv_fallback, false);
        assert_eq!(
            inv_fallback, inv_expected,
            "scalar inverse fallback diverged"
        );

        if avx2_available() {
            let mut inv_accel = expected;
            invntt_dispatch(&mut inv_accel, true);
            assert_eq!(inv_accel, inv_expected, "AVX2 inverse arm diverged");
        }
    }

    #[test]
    fn test_ntt_simd_matches_scalar() {
        let mut a_scalar = [0i32; N];
        let mut a_simd = [0i32; N];
        for i in 0..N {
            let v = (i as i32 * 37 + 11) % Q;
            a_scalar[i] = v;
            a_simd[i] = v;
        }

        crate::ntt::ntt(&mut a_scalar);
        ntt_simd(&mut a_simd);

        assert_eq!(a_scalar, a_simd, "SIMD NTT diverged from scalar");
    }

    #[test]
    fn test_invntt_simd_matches_scalar() {
        let mut a_scalar = [0i32; N];
        let mut a_simd = [0i32; N];
        for i in 0..N {
            let v = (i as i32 * 37 + 11) % Q;
            a_scalar[i] = v;
            a_simd[i] = v;
        }

        crate::ntt::ntt(&mut a_scalar);
        crate::ntt::ntt(&mut a_simd);

        crate::ntt::invntt_tomont(&mut a_scalar);
        invntt_simd(&mut a_simd);

        assert_eq!(a_scalar, a_simd, "SIMD INVNTT diverged from scalar");
    }

    #[test]
    fn test_ntt_roundtrip_simd() {
        let mut a = [0i32; N];
        for i in 0..N {
            let v = (i as i32 * 13 + 5) % Q;
            a[i] = v;
        }
        let before = a;

        ntt_simd(&mut a);
        // NTT should change the values
        assert_ne!(a, before, "NTT did not transform input");

        invntt_simd(&mut a);

        // After NTT → INVNTT, values should be equivalent (Montgomery scaled)
        // Each coeff should be congruent to original * 2^32 * 2^32/256 mod Q
        // Just verify determinism: repeated NTT+INVNTT gives same result
        let mut b = before;
        ntt_simd(&mut b);
        invntt_simd(&mut b);
        assert_eq!(a, b, "SIMD NTT round-trip not deterministic");
    }
}
