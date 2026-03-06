//! Rounding operations for Dilithium.
//!
//! Faithful port of `rounding.c` from the CRYSTALS-Dilithium reference.

use crate::params::{DilithiumMode, D, Q};

/// Power-of-2 rounding.
///
/// For finite field element `a`, compute `a0, a1` such that
/// `a mod^+ Q = a1*2^D + a0` with `-2^{D-1} < a0 <= 2^{D-1}`.
/// Assumes `a` to be standard representative.
///
/// Returns `(a1, a0)`.
#[inline]
#[must_use]
pub fn power2round(a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a0 = a - (a1 << D);
    (a1, a0)
}

/// High/low bit decomposition.
///
/// For finite field element `a`, compute high and low bits `a0, a1` such that
/// `a mod^+ Q = a1*ALPHA + a0` with `-ALPHA/2 < a0 <= ALPHA/2` except
/// if `a1 = (Q-1)/ALPHA` where we set `a1 = 0` and
/// `-ALPHA/2 <= a0 = a mod^+ Q - Q < 0`. Assumes `a` to be standard representative.
///
/// Returns `(a1, a0)`.
#[must_use]
pub fn decompose(mode: DilithiumMode, a: i32) -> (i32, i32) {
    let gamma2 = mode.gamma2();
    let mut a1 = (a + 127) >> 7;

    if gamma2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        // gamma2 == (Q-1)/88
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    let mut a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

/// Compute hint bit indicating whether the low bits of the input element
/// overflow into the high bits.
///
/// Returns `true` if overflow.
#[inline]
#[must_use]
pub fn make_hint(mode: DilithiumMode, a0: i32, a1: i32) -> bool {
    let gamma2 = mode.gamma2();
    a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)
}

/// Correct high bits according to hint.
///
/// Returns corrected high bits.
#[must_use]
pub fn use_hint(mode: DilithiumMode, a: i32, hint: bool) -> i32 {
    let gamma2 = mode.gamma2();
    let (a1, a0) = decompose(mode, a);

    if !hint {
        return a1;
    }

    if gamma2 == (Q - 1) / 32 {
        if a0 > 0 {
            (a1 + 1) & 15
        } else {
            (a1 - 1) & 15
        }
    } else {
        // gamma2 == (Q-1)/88
        if a0 > 0 {
            if a1 == 43 {
                0
            } else {
                a1 + 1
            }
        } else if a1 == 0 {
            43
        } else {
            a1 - 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round_reconstruction() {
        // For all supported values, a1*2^D + a0 should equal a
        for a in [0, 1, 100, 1000, Q / 2, Q - 1] {
            let (a1, a0) = power2round(a);
            assert_eq!(a1 * (1 << D) + a0, a, "power2round failed for a={}", a);
        }
    }

    #[test]
    fn test_decompose_reconstruction() {
        // a1 * 2*gamma2 + a0 ≡ a (mod Q) for standard representatives
        for mode in [
            DilithiumMode::Dilithium2,
            DilithiumMode::Dilithium3,
            DilithiumMode::Dilithium5,
        ] {
            let gamma2 = mode.gamma2();
            for a in [0, 1, 100, 1000, Q / 2, Q - 1] {
                let (a1, a0) = decompose(mode, a);
                let reconstructed = a1 * 2 * gamma2 + a0;
                let reconstructed_mod = if reconstructed < 0 {
                    reconstructed + Q
                } else {
                    reconstructed
                };
                assert_eq!(
                    reconstructed_mod, a,
                    "decompose failed for mode={:?}, a={}",
                    mode, a
                );
            }
        }
    }

    #[test]
    fn test_use_hint_no_hint() {
        // With hint=false, use_hint should return the same as decompose's a1
        for mode in [
            DilithiumMode::Dilithium2,
            DilithiumMode::Dilithium3,
            DilithiumMode::Dilithium5,
        ] {
            for a in [0, 1, 100, Q / 2, Q - 1] {
                let (a1, _) = decompose(mode, a);
                let result = use_hint(mode, a, false);
                assert_eq!(result, a1);
            }
        }
    }
}
