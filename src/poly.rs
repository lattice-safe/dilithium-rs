//! Polynomial operations for Dilithium.
//!
//! Faithful port of `poly.c` from the CRYSTALS-Dilithium reference.
//! Central type: `Poly` with N=256 coefficients in `Z_Q`.

use crate::ntt;
use crate::params::*;
use crate::reduce::{caddq, montgomery_reduce, reduce32};
use crate::rounding;
use crate::symmetric::{Stream128, Stream256};

/// Stream block sizes matching SHAKE rates.
const STREAM128_BLOCKBYTES: usize = 168; // SHAKE128_RATE
const STREAM256_BLOCKBYTES: usize = 136; // SHAKE256_RATE

/// A polynomial in `Z_Q`[X]/(X^N + 1).
#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i32; N] }
    }
}

impl Poly {
    /// Create a zero polynomial.
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }

    // ================================================================
    // Arithmetic
    // ================================================================

    /// In-place reduction of all coefficients to [-6283008, 6283008].
    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce32(self.coeffs[i]);
        }
    }

    /// For all coefficients, add Q if negative.
    pub fn caddq(&mut self) {
        for i in 0..N {
            self.coeffs[i] = caddq(self.coeffs[i]);
        }
    }

    /// Add two polynomials: c = a + b. No modular reduction.
    pub fn add(c: &mut Poly, a: &Poly, b: &Poly) {
        for i in 0..N {
            c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
        }
    }

    /// Subtract polynomials: c = a - b. No modular reduction.
    pub fn sub(c: &mut Poly, a: &Poly, b: &Poly) {
        for i in 0..N {
            c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }

    /// Multiply polynomial by 2^D without modular reduction.
    pub fn shiftl(&mut self) {
        for i in 0..N {
            self.coeffs[i] <<= D;
        }
    }

    /// In-place forward NTT.
    pub fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    /// In-place inverse NTT with Montgomery factor.
    pub fn invntt_tomont(&mut self) {
        ntt::invntt_tomont(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain with Montgomery reduction.
    pub fn pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
        for i in 0..N {
            c.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
    }

    // ================================================================
    // Rounding wrappers
    // ================================================================

    /// Power-of-2 rounding: splits `a` into `(a1, a0)` where `a = a1*2^D + a0`.
    pub fn power2round(a1: &mut Poly, a0: &mut Poly, a: &Poly) {
        for i in 0..N {
            let (high, low) = rounding::power2round(a.coeffs[i]);
            a1.coeffs[i] = high;
            a0.coeffs[i] = low;
        }
    }

    /// Decompose into high and low bits.
    pub fn decompose(mode: DilithiumMode, a1: &mut Poly, a0: &mut Poly, a: &Poly) {
        for i in 0..N {
            let (high, low) = rounding::decompose(mode, a.coeffs[i]);
            a1.coeffs[i] = high;
            a0.coeffs[i] = low;
        }
    }

    /// Compute hint polynomial. Returns number of 1 bits.
    pub fn make_hint(mode: DilithiumMode, h: &mut Poly, a0: &Poly, a1: &Poly) -> usize {
        let mut s: usize = 0;
        for i in 0..N {
            h.coeffs[i] = rounding::make_hint(mode, a0.coeffs[i], a1.coeffs[i]) as i32;
            s += h.coeffs[i] as usize;
        }
        s
    }

    /// Use hint polynomial to correct high bits.
    pub fn use_hint(mode: DilithiumMode, b: &mut Poly, a: &Poly, h: &Poly) {
        for i in 0..N {
            b.coeffs[i] = rounding::use_hint(mode, a.coeffs[i], h.coeffs[i] != 0);
        }
    }

    /// Check infinity norm against bound B.
    /// Returns `true` if norm >= B (i.e., check fails).
    #[must_use]
    pub fn chknorm(&self, bound: i32) -> bool {
        if bound > (Q - 1) / 8 {
            return true;
        }
        for i in 0..N {
            // Absolute value (handle Q/2 boundary)
            let mut t = self.coeffs[i] >> 31;
            t = self.coeffs[i] - (t & (2 * self.coeffs[i]));
            if t >= bound {
                return true;
            }
        }
        false
    }

    // ================================================================
    // Sampling
    // ================================================================

    /// Rejection sampling: sample uniform coefficients in [0, Q-1].
    /// Returns number of coefficients written.
    pub fn rej_uniform(a: &mut [i32], buf: &[u8]) -> usize {
        let len = a.len();
        let buflen = buf.len();
        let mut ctr = 0usize;
        let mut pos = 0usize;

        while ctr < len && pos + 3 <= buflen {
            let mut t = buf[pos] as u32;
            t |= (buf[pos + 1] as u32) << 8;
            t |= (buf[pos + 2] as u32) << 16;
            t &= 0x7FFFFF;
            pos += 3;

            if t < Q as u32 {
                a[ctr] = t as i32;
                ctr += 1;
            }
        }
        ctr
    }

    /// Sample polynomial with uniformly random coefficients in [0, Q-1]
    /// via rejection sampling on output of SHAKE128.
    pub fn uniform(a: &mut Poly, seed: &[u8; SEEDBYTES], nonce: u16) {
        const NBLOCKS: usize = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;

        let mut stream = Stream128::init(seed, nonce);
        let mut buf = [0u8; NBLOCKS * STREAM128_BLOCKBYTES + 2];
        stream.squeeze(&mut buf[..NBLOCKS * STREAM128_BLOCKBYTES]);

        let mut ctr = Self::rej_uniform(&mut a.coeffs[..N], &buf[..NBLOCKS * STREAM128_BLOCKBYTES]);

        while ctr < N {
            let mut tmp = [0u8; STREAM128_BLOCKBYTES];
            stream.squeeze(&mut tmp);
            ctr += Self::rej_uniform(&mut a.coeffs[ctr..N], &tmp);
        }
    }

    /// Rejection sampling for eta-bounded coefficients in [-ETA, ETA].
    pub fn rej_eta(mode: DilithiumMode, a: &mut [i32], buf: &[u8]) -> usize {
        let eta = mode.eta();
        let len = a.len();
        let buflen = buf.len();
        let mut ctr = 0usize;
        let mut pos = 0usize;

        while ctr < len && pos < buflen {
            let t0 = (buf[pos] & 0x0F) as u32;
            let t1 = (buf[pos] >> 4) as u32;
            pos += 1;

            if eta == 2 {
                if t0 < 15 {
                    let t0 = t0
                        .wrapping_sub((t0.wrapping_mul(205)) >> 10 << 2)
                        .wrapping_sub((t0.wrapping_mul(205)) >> 10);
                    // t0 = t0 mod 5, then center: eta - t0
                    a[ctr] = 2 - (t0 % 5) as i32;
                    ctr += 1;
                }
                if t1 < 15 && ctr < len {
                    let t1 = t1
                        .wrapping_sub((t1.wrapping_mul(205)) >> 10 << 2)
                        .wrapping_sub((t1.wrapping_mul(205)) >> 10);
                    a[ctr] = 2 - (t1 % 5) as i32;
                    ctr += 1;
                }
            } else {
                // eta == 4
                if t0 < 9 {
                    a[ctr] = 4 - t0 as i32;
                    ctr += 1;
                }
                if t1 < 9 && ctr < len {
                    a[ctr] = 4 - t1 as i32;
                    ctr += 1;
                }
            }
        }
        ctr
    }

    /// Sample polynomial with coefficients in [-ETA, ETA] via SHAKE256.
    pub fn uniform_eta(mode: DilithiumMode, a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
        let nblocks = if mode.eta() == 2 {
            (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        } else {
            (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        };

        let mut stream = Stream256::init(seed, nonce);
        let mut buf = vec![0u8; nblocks * STREAM256_BLOCKBYTES];
        stream.squeeze(&mut buf);

        let mut ctr = Self::rej_eta(mode, &mut a.coeffs[..N], &buf);
        while ctr < N {
            let mut tmp = [0u8; STREAM256_BLOCKBYTES];
            stream.squeeze(&mut tmp);
            ctr += Self::rej_eta(mode, &mut a.coeffs[ctr..N], &tmp);
        }
    }

    /// Sample polynomial with coefficients in [-(GAMMA1-1), GAMMA1]
    /// by unpacking SHAKE256 stream output.
    pub fn uniform_gamma1(mode: DilithiumMode, a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
        let polyz_packed = mode.polyz_packedbytes();
        let nblocks = (polyz_packed + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;

        let mut stream = Stream256::init(seed, nonce);
        let mut buf = vec![0u8; nblocks * STREAM256_BLOCKBYTES];
        stream.squeeze(&mut buf);

        Self::polyz_unpack(mode, a, &buf);
    }

    /// Sample challenge polynomial with TAU nonzero coefficients in {-1, 1}
    /// using SHAKE256(seed).
    pub fn challenge(mode: DilithiumMode, c: &mut Poly, seed: &[u8]) {
        use crate::symmetric::Shake256State;

        let tau = mode.tau();

        let mut state = Shake256State::new();
        state.absorb(seed);
        let mut reader = state.finalize();

        let mut buf = [0u8; 8];
        reader.squeeze(&mut buf);
        let mut signs: u64 = u64::from_le_bytes(buf);

        *c = Poly::zero();

        for i in (N - tau)..N {
            let mut b = [0u8; 1];
            loop {
                reader.squeeze(&mut b);
                if (b[0] as usize) <= i {
                    break;
                }
            }
            let j = b[0] as usize;
            c.coeffs[i] = c.coeffs[j];
            c.coeffs[j] = 1 - 2 * (signs & 1) as i32;
            signs >>= 1;
        }
    }

    // ================================================================
    // Bit-packing
    // ================================================================

    /// Pack polynomial with eta-bounded coefficients.
    pub fn polyeta_pack(mode: DilithiumMode, r: &mut [u8], a: &Poly) {
        let eta = mode.eta();
        if eta == 2 {
            for i in 0..(N / 8) {
                let mut t = [0u8; 8];
                for j in 0..8 {
                    t[j] = (eta - a.coeffs[8 * i + j]) as u8;
                }
                r[3 * i + 0] = t[0] | (t[1] << 3) | (t[2] << 6);
                r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
            }
        } else {
            // eta == 4
            for i in 0..(N / 2) {
                let t0 = (eta - a.coeffs[2 * i + 0]) as u8;
                let t1 = (eta - a.coeffs[2 * i + 1]) as u8;
                r[i] = t0 | (t1 << 4);
            }
        }
    }

    /// Unpack polynomial with eta-bounded coefficients.
    pub fn polyeta_unpack(mode: DilithiumMode, r: &mut Poly, a: &[u8]) {
        let eta = mode.eta();
        if eta == 2 {
            for i in 0..(N / 8) {
                r.coeffs[8 * i + 0] = ((a[3 * i + 0]) & 7) as i32;
                r.coeffs[8 * i + 1] = ((a[3 * i + 0] >> 3) & 7) as i32;
                r.coeffs[8 * i + 2] = (((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7) as i32;
                r.coeffs[8 * i + 3] = ((a[3 * i + 1] >> 1) & 7) as i32;
                r.coeffs[8 * i + 4] = ((a[3 * i + 1] >> 4) & 7) as i32;
                r.coeffs[8 * i + 5] = (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7) as i32;
                r.coeffs[8 * i + 6] = ((a[3 * i + 2] >> 2) & 7) as i32;
                r.coeffs[8 * i + 7] = ((a[3 * i + 2] >> 5) & 7) as i32;

                for j in 0..8 {
                    r.coeffs[8 * i + j] = eta - r.coeffs[8 * i + j];
                }
            }
        } else {
            // eta == 4
            for i in 0..(N / 2) {
                r.coeffs[2 * i + 0] = (a[i] & 0x0F) as i32;
                r.coeffs[2 * i + 1] = (a[i] >> 4) as i32;
                r.coeffs[2 * i + 0] = eta - r.coeffs[2 * i + 0];
                r.coeffs[2 * i + 1] = eta - r.coeffs[2 * i + 1];
            }
        }
    }

    /// Pack t1 polynomial (10-bit coefficients).
    pub fn polyt1_pack(r: &mut [u8], a: &Poly) {
        for i in 0..(N / 4) {
            r[5 * i + 0] = a.coeffs[4 * i + 0] as u8;
            r[5 * i + 1] = ((a.coeffs[4 * i + 0] >> 8) | (a.coeffs[4 * i + 1] << 2)) as u8;
            r[5 * i + 2] = ((a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4)) as u8;
            r[5 * i + 3] = ((a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6)) as u8;
            r[5 * i + 4] = (a.coeffs[4 * i + 3] >> 2) as u8;
        }
    }

    /// Unpack t1 polynomial (10-bit coefficients).
    pub fn polyt1_unpack(r: &mut Poly, a: &[u8]) {
        for i in 0..(N / 4) {
            r.coeffs[4 * i + 0] =
                ((a[5 * i + 0] as u32 | ((a[5 * i + 1] as u32) << 8)) & 0x3FF) as i32;
            r.coeffs[4 * i + 1] =
                (((a[5 * i + 1] as u32 >> 2) | ((a[5 * i + 2] as u32) << 6)) & 0x3FF) as i32;
            r.coeffs[4 * i + 2] =
                (((a[5 * i + 2] as u32 >> 4) | ((a[5 * i + 3] as u32) << 4)) & 0x3FF) as i32;
            r.coeffs[4 * i + 3] =
                ((a[5 * i + 3] as u32 >> 6) | ((a[5 * i + 4] as u32) << 2)) as i32;
        }
    }

    /// Pack t0 polynomial (13-bit coefficients in ]-2^{D-1}, 2^{D-1}]).
    pub fn polyt0_pack(r: &mut [u8], a: &Poly) {
        let mut t = [0i32; 8];
        for i in 0..(N / 8) {
            for j in 0..8 {
                t[j] = (1 << (D - 1)) - a.coeffs[8 * i + j];
            }
            r[13 * i + 0] = t[0] as u8;
            r[13 * i + 1] = (t[0] >> 8) as u8;
            r[13 * i + 1] |= (t[1] << 5) as u8;
            r[13 * i + 2] = (t[1] >> 3) as u8;
            r[13 * i + 3] = (t[1] >> 11) as u8;
            r[13 * i + 3] |= (t[2] << 2) as u8;
            r[13 * i + 4] = (t[2] >> 6) as u8;
            r[13 * i + 4] |= (t[3] << 7) as u8;
            r[13 * i + 5] = (t[3] >> 1) as u8;
            r[13 * i + 6] = (t[3] >> 9) as u8;
            r[13 * i + 6] |= (t[4] << 4) as u8;
            r[13 * i + 7] = (t[4] >> 4) as u8;
            r[13 * i + 8] = (t[4] >> 12) as u8;
            r[13 * i + 8] |= (t[5] << 1) as u8;
            r[13 * i + 9] = (t[5] >> 7) as u8;
            r[13 * i + 9] |= (t[6] << 6) as u8;
            r[13 * i + 10] = (t[6] >> 2) as u8;
            r[13 * i + 11] = (t[6] >> 10) as u8;
            r[13 * i + 11] |= (t[7] << 3) as u8;
            r[13 * i + 12] = (t[7] >> 5) as u8;
        }
    }

    /// Unpack t0 polynomial (13-bit coefficients).
    pub fn polyt0_unpack(r: &mut Poly, a: &[u8]) {
        for i in 0..(N / 8) {
            r.coeffs[8 * i + 0] = a[13 * i + 0] as i32;
            r.coeffs[8 * i + 0] |= (a[13 * i + 1] as i32) << 8;
            r.coeffs[8 * i + 0] &= 0x1FFF;

            r.coeffs[8 * i + 1] = (a[13 * i + 1] as i32) >> 5;
            r.coeffs[8 * i + 1] |= (a[13 * i + 2] as i32) << 3;
            r.coeffs[8 * i + 1] |= (a[13 * i + 3] as i32) << 11;
            r.coeffs[8 * i + 1] &= 0x1FFF;

            r.coeffs[8 * i + 2] = (a[13 * i + 3] as i32) >> 2;
            r.coeffs[8 * i + 2] |= (a[13 * i + 4] as i32) << 6;
            r.coeffs[8 * i + 2] &= 0x1FFF;

            r.coeffs[8 * i + 3] = (a[13 * i + 4] as i32) >> 7;
            r.coeffs[8 * i + 3] |= (a[13 * i + 5] as i32) << 1;
            r.coeffs[8 * i + 3] |= (a[13 * i + 6] as i32) << 9;
            r.coeffs[8 * i + 3] &= 0x1FFF;

            r.coeffs[8 * i + 4] = (a[13 * i + 6] as i32) >> 4;
            r.coeffs[8 * i + 4] |= (a[13 * i + 7] as i32) << 4;
            r.coeffs[8 * i + 4] |= (a[13 * i + 8] as i32) << 12;
            r.coeffs[8 * i + 4] &= 0x1FFF;

            r.coeffs[8 * i + 5] = (a[13 * i + 8] as i32) >> 1;
            r.coeffs[8 * i + 5] |= (a[13 * i + 9] as i32) << 7;
            r.coeffs[8 * i + 5] &= 0x1FFF;

            r.coeffs[8 * i + 6] = (a[13 * i + 9] as i32) >> 6;
            r.coeffs[8 * i + 6] |= (a[13 * i + 10] as i32) << 2;
            r.coeffs[8 * i + 6] |= (a[13 * i + 11] as i32) << 10;
            r.coeffs[8 * i + 6] &= 0x1FFF;

            r.coeffs[8 * i + 7] = (a[13 * i + 11] as i32) >> 3;
            r.coeffs[8 * i + 7] |= (a[13 * i + 12] as i32) << 5;
            r.coeffs[8 * i + 7] &= 0x1FFF;

            for j in 0..8 {
                r.coeffs[8 * i + j] = (1 << (D - 1)) - r.coeffs[8 * i + j];
            }
        }
    }

    /// Pack z polynomial with coefficients in [-(GAMMA1-1), GAMMA1].
    pub fn polyz_pack(mode: DilithiumMode, r: &mut [u8], a: &Poly) {
        let gamma1 = mode.gamma1();
        if gamma1 == (1 << 17) {
            // 18-bit values
            for i in 0..(N / 4) {
                let mut t = [0u32; 4];
                for j in 0..4 {
                    t[j] = (gamma1 - a.coeffs[4 * i + j]) as u32;
                }
                r[9 * i + 0] = t[0] as u8;
                r[9 * i + 1] = (t[0] >> 8) as u8;
                r[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
                r[9 * i + 3] = (t[1] >> 6) as u8;
                r[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
                r[9 * i + 5] = (t[2] >> 4) as u8;
                r[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
                r[9 * i + 7] = (t[3] >> 2) as u8;
                r[9 * i + 8] = (t[3] >> 10) as u8;
            }
        } else {
            // gamma1 == 2^19, 20-bit values
            for i in 0..(N / 2) {
                let t0 = (gamma1 - a.coeffs[2 * i + 0]) as u32;
                let t1 = (gamma1 - a.coeffs[2 * i + 1]) as u32;
                r[5 * i + 0] = t0 as u8;
                r[5 * i + 1] = (t0 >> 8) as u8;
                r[5 * i + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
                r[5 * i + 3] = (t1 >> 4) as u8;
                r[5 * i + 4] = (t1 >> 12) as u8;
            }
        }
    }

    /// Unpack z polynomial.
    pub fn polyz_unpack(mode: DilithiumMode, r: &mut Poly, a: &[u8]) {
        let gamma1 = mode.gamma1();
        if gamma1 == (1 << 17) {
            for i in 0..(N / 4) {
                r.coeffs[4 * i + 0] = a[9 * i + 0] as i32;
                r.coeffs[4 * i + 0] |= (a[9 * i + 1] as i32) << 8;
                r.coeffs[4 * i + 0] |= (a[9 * i + 2] as i32) << 16;
                r.coeffs[4 * i + 0] &= 0x3FFFF;

                r.coeffs[4 * i + 1] = (a[9 * i + 2] as i32) >> 2;
                r.coeffs[4 * i + 1] |= (a[9 * i + 3] as i32) << 6;
                r.coeffs[4 * i + 1] |= (a[9 * i + 4] as i32) << 14;
                r.coeffs[4 * i + 1] &= 0x3FFFF;

                r.coeffs[4 * i + 2] = (a[9 * i + 4] as i32) >> 4;
                r.coeffs[4 * i + 2] |= (a[9 * i + 5] as i32) << 4;
                r.coeffs[4 * i + 2] |= (a[9 * i + 6] as i32) << 12;
                r.coeffs[4 * i + 2] &= 0x3FFFF;

                r.coeffs[4 * i + 3] = (a[9 * i + 6] as i32) >> 6;
                r.coeffs[4 * i + 3] |= (a[9 * i + 7] as i32) << 2;
                r.coeffs[4 * i + 3] |= (a[9 * i + 8] as i32) << 10;
                r.coeffs[4 * i + 3] &= 0x3FFFF;

                for j in 0..4 {
                    r.coeffs[4 * i + j] = gamma1 - r.coeffs[4 * i + j];
                }
            }
        } else {
            // gamma1 == 2^19
            for i in 0..(N / 2) {
                r.coeffs[2 * i + 0] = a[5 * i + 0] as i32;
                r.coeffs[2 * i + 0] |= (a[5 * i + 1] as i32) << 8;
                r.coeffs[2 * i + 0] |= (a[5 * i + 2] as i32) << 16;
                r.coeffs[2 * i + 0] &= 0xFFFFF;

                r.coeffs[2 * i + 1] = (a[5 * i + 2] as i32) >> 4;
                r.coeffs[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
                r.coeffs[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;
                r.coeffs[2 * i + 1] &= 0xFFFFF;

                for j in 0..2 {
                    r.coeffs[2 * i + j] = gamma1 - r.coeffs[2 * i + j];
                }
            }
        }
    }

    /// Pack w1 polynomial.
    pub fn polyw1_pack(mode: DilithiumMode, r: &mut [u8], a: &Poly) {
        let gamma2 = mode.gamma2();
        if gamma2 == (Q - 1) / 88 {
            // coefficients in [0, 43] -> 6 bits
            for i in 0..(N / 4) {
                r[3 * i + 0] = a.coeffs[4 * i + 0] as u8;
                r[3 * i + 0] |= (a.coeffs[4 * i + 1] << 6) as u8;
                r[3 * i + 1] = (a.coeffs[4 * i + 1] >> 2) as u8;
                r[3 * i + 1] |= (a.coeffs[4 * i + 2] << 4) as u8;
                r[3 * i + 2] = (a.coeffs[4 * i + 2] >> 4) as u8;
                r[3 * i + 2] |= (a.coeffs[4 * i + 3] << 2) as u8;
            }
        } else {
            // gamma2 == (Q-1)/32, coefficients in [0, 15] -> 4 bits
            for i in 0..(N / 2) {
                r[i] = (a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4)) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyt1_pack_unpack_roundtrip() {
        let mut a = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = (i as i32 * 3 + 7) & 0x3FF; // 10-bit values
        }
        let mut buf = [0u8; POLYT1_PACKEDBYTES];
        Poly::polyt1_pack(&mut buf, &a);
        let mut b = Poly::zero();
        Poly::polyt1_unpack(&mut b, &buf);
        assert_eq!(a.coeffs, b.coeffs);
    }

    #[test]
    fn test_polyt0_pack_unpack_roundtrip() {
        let mut a = Poly::zero();
        for i in 0..N {
            // t0 coefficients in ]-2^{D-1}, 2^{D-1}], i.e. (-4096, 4096]
            a.coeffs[i] = -4095 + (i as i32 * 31) % 8191;
        }
        let mut buf = [0u8; POLYT0_PACKEDBYTES];
        Poly::polyt0_pack(&mut buf, &a);
        let mut b = Poly::zero();
        Poly::polyt0_unpack(&mut b, &buf);
        assert_eq!(a.coeffs, b.coeffs);
    }

    #[test]
    fn test_polyeta_pack_unpack_roundtrip() {
        for mode in [
            DilithiumMode::Dilithium2,
            DilithiumMode::Dilithium3,
            DilithiumMode::Dilithium5,
        ] {
            let eta = mode.eta();
            let mut a = Poly::zero();
            for i in 0..N {
                a.coeffs[i] = -(eta) + ((i as i32) % (2 * eta + 1));
            }
            let mut buf = vec![0u8; mode.polyeta_packedbytes()];
            Poly::polyeta_pack(mode, &mut buf, &a);
            let mut b = Poly::zero();
            Poly::polyeta_unpack(mode, &mut b, &buf);
            assert_eq!(
                a.coeffs, b.coeffs,
                "polyeta roundtrip failed for {:?}",
                mode
            );
        }
    }

    #[test]
    fn test_polyz_pack_unpack_roundtrip() {
        for mode in [
            DilithiumMode::Dilithium2,
            DilithiumMode::Dilithium3,
            DilithiumMode::Dilithium5,
        ] {
            let gamma1 = mode.gamma1();
            let mut a = Poly::zero();
            for i in 0..N {
                a.coeffs[i] = -(gamma1 - 1) + ((i as i32 * 997) % (2 * gamma1 - 1));
            }
            let mut buf = vec![0u8; mode.polyz_packedbytes()];
            Poly::polyz_pack(mode, &mut buf, &a);
            let mut b = Poly::zero();
            Poly::polyz_unpack(mode, &mut b, &buf);
            assert_eq!(a.coeffs, b.coeffs, "polyz roundtrip failed for {:?}", mode);
        }
    }

    #[test]
    fn test_chknorm() {
        let mut a = Poly::zero();
        a.coeffs[0] = 100;
        assert!(!a.chknorm(101));
        assert!(a.chknorm(100));
        assert!(a.chknorm(50));
    }
}
