//! Modular arithmetic: Montgomery reduction and Barrett-like reduction.
//!
//! Faithful port of `reduce.c` from the CRYSTALS-Dilithium reference.

use crate::params::{Q, QINV};

/// Montgomery reduction.
///
/// For finite field element `a` with `-2^{31}*Q <= a <= Q*2^{31}`,
/// compute `r ≡ a * 2^{-32} (mod Q)` such that `-Q < r < Q`.
#[inline]
#[must_use]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV as i32);
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// Barrett-like reduction.
///
/// For finite field element `a` with `a <= 2^{31} - 2^{22} - 1`,
/// compute `r ≡ a (mod Q)` such that `-6283008 <= r <= 6283008`.
#[inline]
#[must_use]
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Conditional addition of Q.
///
/// Add Q if input coefficient is negative.
#[inline]
#[must_use]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Full canonical reduction: standard representative `r = a mod^+ Q`.
#[inline]
#[must_use]
pub fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce_zero() {
        assert_eq!(montgomery_reduce(0), 0);
    }

    #[test]
    fn test_reduce32_small() {
        // Q should reduce to 0
        assert_eq!(reduce32(Q), 0);
        assert_eq!(reduce32(0), 0);
    }

    #[test]
    fn test_caddq_negative() {
        assert_eq!(caddq(-1), Q - 1);
        assert_eq!(caddq(0), 0);
        assert_eq!(caddq(1), 1);
    }

    #[test]
    fn test_freeze_identity() {
        // freeze(x) for x in [0, Q) should be x
        for x in [0, 1, 100, Q - 1] {
            assert_eq!(freeze(x), x);
        }
    }

    #[test]
    fn test_freeze_negative() {
        // freeze(-1) should give Q-1
        let r = freeze(-1);
        assert_eq!(r, Q - 1);
    }

    #[test]
    fn test_montgomery_round_trip() {
        // Montgomery form: a_mont = a * 2^32 mod Q
        // montgomery_reduce(a_mont * b_mont) = a*b * 2^32 mod Q
        let a: i64 = 42;
        let b: i64 = 123;
        let ab = a * b;
        // montgomery_reduce(ab) = ab * 2^{-32} mod Q
        let r = montgomery_reduce(ab);
        // r should be in (-Q, Q)
        assert!(r > -Q && r < Q);
    }
}
