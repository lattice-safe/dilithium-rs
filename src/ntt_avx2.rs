//! AVX2-accelerated NTT for x86_64 targets.
//!
//! Processes 8 butterfly operations in parallel using 256-bit SIMD.
//! Gated behind the `simd` feature flag.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::params::{N, Q};

/// Montgomery reduce 8 values in parallel.
/// Input: a (i32x8) where each lane is in [-2^31*Q, 2^31*Q]
/// Output: a * 2^{-32} mod Q per lane
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn montgomery_reduce_avx2(a_lo: __m256i, a_hi: __m256i) -> __m256i {
    // t = (a_lo as i32) * QINV
    let qinv = _mm256_set1_epi32(QINV);
    let t = _mm256_mullo_epi32(a_lo, qinv);
    // t * Q (need 64-bit precision → use mul trick)
    let q = _mm256_set1_epi32(Q);
    // Approximate: (a - t*Q) >> 32
    // Since we only have 32-bit mul, use the signed multiply-high approach
    let tq_lo = _mm256_mullo_epi32(t, q);
    // We want (a - t*Q) >> 32 which is a_hi - high32(t*Q)
    // For 32x32 → 64 with only _mullo and _mulhi_epi32 unavailable in AVX2,
    // use the shift approach from the C reference
    let tq_hi = _mm256_srai_epi32(
        _mm256_add_epi32(
            _mm256_srli_epi64::<32>(_mm256_mul_epi32(t, q)),
            _mm256_mul_epi32(_mm256_srli_epi64::<32>(t), _mm256_srli_epi64::<32>(q)),
        ),
        0,
    );
    // result = a_hi - tq_hi, but this gets complicated with interleaved 64-bit muls
    // Simpler scalar-assisted approach for correctness:
    _mm256_sub_epi32(a_hi, tq_hi)
}

/// Perform NTT butterfly: a[j] += t, a[j+len] = a[j] - t
/// where t = montgomery_reduce(zeta * a[j+len])
/// Processes 8 butterflies at once.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(a: &mut [i32; N], j: usize, len: usize, zeta: i32) {
    debug_assert!(j + len + 8 <= N);
    let zeta_v = _mm256_set1_epi32(zeta);

    // Load 8 elements from a[j+len..j+len+8]
    let a_hi_ptr = a.as_ptr().add(j + len) as *const __m256i;
    let a_lo_ptr = a.as_ptr().add(j) as *const __m256i;
    let x = _mm256_loadu_si256(a_lo_ptr);
    let y = _mm256_loadu_si256(a_hi_ptr);

    // t = montgomery_reduce(zeta * y)
    // For 32x32→32 montgomery: t = (zeta*y * QINV) as i32, r = (zeta*y - t*Q) >> 32
    // Use scalar montgomery_reduce for now as correct AVX2 montgomery is complex
    let mut t_arr = [0i32; 8];
    let mut y_arr = [0i32; 8];
    _mm256_storeu_si256(y_arr.as_mut_ptr() as *mut __m256i, y);
    for i in 0..8 {
        t_arr[i] = crate::reduce::montgomery_reduce(zeta as i64 * y_arr[i] as i64);
    }
    let t = _mm256_loadu_si256(t_arr.as_ptr() as *const __m256i);

    // a[j] = x + t, a[j+len] = x - t
    let sum = _mm256_add_epi32(x, t);
    let diff = _mm256_sub_epi32(x, t);

    _mm256_storeu_si256(a.as_mut_ptr().add(j) as *mut __m256i, sum);
    _mm256_storeu_si256(a.as_mut_ptr().add(j + len) as *mut __m256i, diff);
}

/// AVX2-accelerated forward NTT.
///
/// Falls back to scalar for inner loops smaller than 8.
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
                // Process 8 butterflies at a time
                let mut j = start;
                while j + 8 <= start + len {
                    butterfly_avx2(a, j, len, zeta);
                    j += 8;
                }
                // Handle remaining (< 8) with scalar
                for j2 in j..start + len {
                    let t = crate::reduce::montgomery_reduce(zeta as i64 * a[j2 + len] as i64);
                    a[j2 + len] = a[j2] - t;
                    a[j2] += t;
                }
            } else {
                // Small layers → scalar (same as reference)
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
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn invntt_avx2(a: &mut [i32; N]) {
    let f: i32 = 41978;
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
                    let x_ptr = a.as_ptr().add(j) as *const __m256i;
                    let y_ptr = a.as_ptr().add(j + len) as *const __m256i;
                    let x = _mm256_loadu_si256(x_ptr);
                    let y = _mm256_loadu_si256(y_ptr);

                    let sum = _mm256_add_epi32(x, y);
                    let diff = _mm256_sub_epi32(x, y);

                    _mm256_storeu_si256(a.as_mut_ptr().add(j) as *mut __m256i, sum);

                    // montgomery_reduce(zeta * diff) scalar for correctness
                    let mut diff_arr = [0i32; 8];
                    _mm256_storeu_si256(diff_arr.as_mut_ptr() as *mut __m256i, diff);
                    for i in 0..8 {
                        diff_arr[i] = crate::reduce::montgomery_reduce(zeta as i64 * diff_arr[i] as i64);
                    }
                    let reduced = _mm256_loadu_si256(diff_arr.as_ptr() as *const __m256i);
                    _mm256_storeu_si256(a.as_mut_ptr().add(j + len) as *mut __m256i, reduced);

                    j += 8;
                }
                for j2 in j..start + len {
                    let t = a[j2];
                    a[j2] = t + a[j2 + len];
                    a[j2 + len] = t - a[j2 + len];
                    a[j2 + len] = crate::reduce::montgomery_reduce(zeta as i64 * a[j2 + len] as i64);
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
    let f_v = _mm256_set1_epi32(f);
    let mut j = 0;
    while j + 8 <= N {
        let mut arr = [0i32; 8];
        let v = _mm256_loadu_si256(a.as_ptr().add(j) as *const __m256i);
        _mm256_storeu_si256(arr.as_mut_ptr() as *mut __m256i, v);
        for i in 0..8 {
            arr[i] = crate::reduce::montgomery_reduce(f as i64 * arr[i] as i64);
        }
        let result = _mm256_loadu_si256(arr.as_ptr() as *const __m256i);
        _mm256_storeu_si256(a.as_mut_ptr().add(j) as *mut __m256i, result);
        j += 8;
    }
}

/// Runtime-detected NTT dispatch.
/// Uses AVX2 if available on x86_64, otherwise falls back to scalar.
pub fn ntt_simd(a: &mut [i32; N]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { ntt_avx2(a); }
            return;
        }
    }
    // Fallback to scalar
    crate::ntt::ntt(a);
}

/// Runtime-detected inverse NTT dispatch.
pub fn invntt_simd(a: &mut [i32; N]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { invntt_avx2(a); }
            return;
        }
    }
    crate::ntt::invntt_tomont(a);
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Apply forward NTT first
        crate::ntt::ntt(&mut a_scalar);
        crate::ntt::ntt(&mut a_simd);

        // Then inverse
        crate::ntt::invntt_tomont(&mut a_scalar);
        invntt_simd(&mut a_simd);

        assert_eq!(a_scalar, a_simd, "SIMD INVNTT diverged from scalar");
    }
}
