//! NEON-accelerated NTT for AArch64 targets (Apple Silicon, ARM servers).
//!
//! Processes 4 butterfly operations in parallel using 128-bit NEON SIMD.
//! Uses `vqdmull` for 32×32→64 signed multiply and lane-based
//! Montgomery reduction.
//!
//! Gated behind the `simd` feature flag. Falls back to scalar on
//! non-aarch64 or when NEON is not available.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[cfg(target_arch = "aarch64")]
use crate::ntt::ZETAS;
use crate::params::N;
#[cfg(target_arch = "aarch64")]
use crate::params::QINV;
// `Q` is referenced from the aarch64 NEON kernels and the SIMD-vs-scalar tests
// (which run on every arch).
#[cfg(any(target_arch = "aarch64", test))]
use crate::params::Q;

/// Pure NEON Montgomery reduction of 4 products.
///
/// Input: `zeta` broadcast, `y` = 4 coefficients.
/// Computes: `montgomery_reduce(zeta * y[i])` for each lane.
///
/// Strategy: compute `a = zeta * y` as 64-bit (two pairs using vmull),
/// then `t = (a_lo * QINV) as i32`, `r = (a - t*Q) >> 32`.
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn montgomery_mul_neon(zeta: int32x4_t, y: int32x4_t) -> int32x4_t {
    let q_v = vdupq_n_s32(Q);
    let qinv_v = vdupq_n_s32(QINV as i32);

    // Split into low/high pairs for 32×32→64 multiply
    let zeta_lo = vget_low_s32(zeta);
    let zeta_hi = vget_high_s32(zeta);
    let y_lo = vget_low_s32(y);
    let y_hi = vget_high_s32(y);

    // a = zeta * y → 64-bit per lane
    let a_lo = vmull_s32(zeta_lo, y_lo); // lanes 0,1
    let a_hi = vmull_s32(zeta_hi, y_hi); // lanes 2,3

    // t = (a_lo32 * QINV) as i32 — only need low 32 bits
    let a_lo32_lo = vmovn_s64(a_lo); // truncate to i32
    let a_lo32_hi = vmovn_s64(a_hi);
    let qinv_lo = vget_low_s32(qinv_v);
    let qinv_hi = vget_high_s32(qinv_v);

    // t * QINV → only low 32 bits matter (wrapping multiply)
    let t_lo = vmul_s32(a_lo32_lo, qinv_lo);
    let t_hi = vmul_s32(a_lo32_hi, qinv_hi);

    // t * Q → 64-bit
    let q_lo = vget_low_s32(q_v);
    let q_hi = vget_high_s32(q_v);
    let tq_lo = vmull_s32(t_lo, q_lo);
    let tq_hi = vmull_s32(t_hi, q_hi);

    // r = (a - t*Q) >> 32
    let r_lo = vshrn_n_s64::<32>(vsubq_s64(a_lo, tq_lo));
    let r_hi = vshrn_n_s64::<32>(vsubq_s64(a_hi, tq_hi));

    // Combine back to 4-lane i32
    vcombine_s32(r_lo, r_hi)
}

/// NEON NTT butterfly on 4 elements.
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn butterfly_neon(a: &mut [i32; N], j: usize, len: usize, zeta: i32) {
    let zeta_v = vdupq_n_s32(zeta);
    let x = vld1q_s32(a.as_ptr().add(j));
    let y = vld1q_s32(a.as_ptr().add(j + len));

    let t = montgomery_mul_neon(zeta_v, y);

    vst1q_s32(a.as_mut_ptr().add(j), vaddq_s32(x, t));
    vst1q_s32(a.as_mut_ptr().add(j + len), vsubq_s32(x, t));
}

/// NEON inverse NTT butterfly on 4 elements.
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn inv_butterfly_neon(a: &mut [i32; N], j: usize, len: usize, zeta_neg: i32) {
    let zeta_v = vdupq_n_s32(zeta_neg);
    let x = vld1q_s32(a.as_ptr().add(j));
    let y = vld1q_s32(a.as_ptr().add(j + len));

    let sum = vaddq_s32(x, y);
    let diff = vsubq_s32(x, y);
    let reduced = montgomery_mul_neon(zeta_v, diff);

    vst1q_s32(a.as_mut_ptr().add(j), sum);
    vst1q_s32(a.as_mut_ptr().add(j + len), reduced);
}

/// NEON-accelerated forward NTT.
///
/// # Safety
/// Requires AArch64 NEON (always available on aarch64). Use `ntt_simd` for safe dispatch.
#[cfg(target_arch = "aarch64")]
pub unsafe fn ntt_neon(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            if len >= 4 {
                let mut j = start;
                while j + 4 <= start + len {
                    butterfly_neon(a, j, len, zeta);
                    j += 4;
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

/// NEON-accelerated inverse NTT.
///
/// # Safety
/// Requires AArch64 NEON (always available on aarch64). Use `invntt_simd` for safe dispatch.
#[cfg(target_arch = "aarch64")]
pub unsafe fn invntt_neon(a: &mut [i32; N]) {
    let f: i32 = 41978;
    let mut k: usize = 256;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            if len >= 4 {
                let mut j = start;
                while j + 4 <= start + len {
                    inv_butterfly_neon(a, j, len, zeta);
                    j += 4;
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

    // Final Montgomery scaling
    let f_v = vdupq_n_s32(f);
    let mut j = 0;
    while j + 4 <= N {
        let v = vld1q_s32(a.as_ptr().add(j));
        let scaled = montgomery_mul_neon(f_v, v);
        vst1q_s32(a.as_mut_ptr().add(j), scaled);
        j += 4;
    }
}

/// NEON is architectural on AArch64 — no runtime detection needed.
#[must_use]
pub fn neon_available() -> bool {
    cfg!(target_arch = "aarch64")
}

/// NTT with the kernel chosen by the caller. Split out from [`ntt_simd`] so
/// both arms are reachable in tests — see the AVX2 module for the rationale.
pub fn ntt_dispatch(a: &mut [i32; N], use_neon: bool) {
    #[cfg(target_arch = "aarch64")]
    if use_neon {
        // SAFETY: NEON is guaranteed on AArch64.
        unsafe {
            ntt_neon(a);
        }
        return;
    }
    let _ = use_neon;
    crate::ntt::ntt(a);
}

/// Inverse NTT with the kernel chosen by the caller. See [`ntt_dispatch`].
pub fn invntt_dispatch(a: &mut [i32; N], use_neon: bool) {
    #[cfg(target_arch = "aarch64")]
    if use_neon {
        // SAFETY: as in `ntt_dispatch`.
        unsafe {
            invntt_neon(a);
        }
        return;
    }
    let _ = use_neon;
    crate::ntt::invntt_tomont(a);
}

/// NTT dispatch (AArch64).
pub fn ntt_simd(a: &mut [i32; N]) {
    ntt_dispatch(a, neon_available());
}

/// Inverse NTT dispatch (AArch64).
pub fn invntt_simd(a: &mut [i32; N]) {
    invntt_dispatch(a, neon_available());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both dispatch arms must agree with the scalar transform.
    #[test]
    fn test_both_dispatch_arms_match_scalar() {
        let mut reference = [0i32; N];
        for i in 0..N {
            reference[i] = (i as i32 * 37 + 11) % Q;
        }
        let mut expected = reference;
        crate::ntt::ntt(&mut expected);

        let mut fallback = reference;
        ntt_dispatch(&mut fallback, false);
        assert_eq!(fallback, expected, "scalar fallback arm diverged");

        if neon_available() {
            let mut accel = reference;
            ntt_dispatch(&mut accel, true);
            assert_eq!(accel, expected, "NEON arm diverged from scalar");
        }

        let mut inv_expected = expected;
        crate::ntt::invntt_tomont(&mut inv_expected);

        let mut inv_fallback = expected;
        invntt_dispatch(&mut inv_fallback, false);
        assert_eq!(
            inv_fallback, inv_expected,
            "scalar inverse fallback diverged"
        );

        if neon_available() {
            let mut inv_accel = expected;
            invntt_dispatch(&mut inv_accel, true);
            assert_eq!(inv_accel, inv_expected, "NEON inverse arm diverged");
        }
    }

    #[test]
    fn test_ntt_neon_matches_scalar() {
        let mut a_scalar = [0i32; N];
        let mut a_simd = [0i32; N];
        for i in 0..N {
            let v = (i as i32 * 37 + 11) % Q;
            a_scalar[i] = v;
            a_simd[i] = v;
        }

        crate::ntt::ntt(&mut a_scalar);
        ntt_simd(&mut a_simd);

        assert_eq!(a_scalar, a_simd, "NEON NTT diverged from scalar");
    }

    #[test]
    fn test_invntt_neon_matches_scalar() {
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

        assert_eq!(a_scalar, a_simd, "NEON INVNTT diverged from scalar");
    }
}
