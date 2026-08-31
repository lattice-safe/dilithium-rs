//! Polynomial operations for Dilithium.
//!
//! Faithful port of `poly.c` from the CRYSTALS-Dilithium reference.
//! Central type: `Poly` with N=256 coefficients in `Z_Q`.

use alloc::vec;
use zeroize::Zeroize;

use crate::params::*;
use crate::reduce::{caddq, montgomery_reduce, reduce32};
use crate::rounding;
use crate::symmetric::{Stream128, Stream256, XofStream};

/// Stream block sizes matching SHAKE rates.
const STREAM128_BLOCKBYTES: usize = 168; // SHAKE128_RATE
const STREAM256_BLOCKBYTES: usize = 136; // SHAKE256_RATE

/// A polynomial in the ring `Z_Q[X]/(X^N + 1)`.
#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i32; N] }
    }
}

impl zeroize::Zeroize for Poly {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.coeffs);
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

    /// In-place addition: r += b. No modular reduction.
    ///
    /// Avoids the temporary clone required by [`Poly::add`], which matters
    /// when the operands hold secret data (no stray copies to zeroize).
    pub fn add_assign(r: &mut Poly, b: &Poly) {
        for i in 0..N {
            r.coeffs[i] += b.coeffs[i];
        }
    }

    /// Subtract polynomials: c = a - b. No modular reduction.
    pub fn sub(c: &mut Poly, a: &Poly, b: &Poly) {
        for i in 0..N {
            c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }

    /// In-place subtraction: r -= b. No modular reduction.
    pub fn sub_assign(r: &mut Poly, b: &Poly) {
        for i in 0..N {
            r.coeffs[i] -= b.coeffs[i];
        }
    }

    /// Multiply polynomial by 2^D without modular reduction.
    pub fn shiftl(&mut self) {
        for i in 0..N {
            self.coeffs[i] <<= D;
        }
    }

    /// In-place forward NTT.
    ///
    /// With the `simd` feature, dispatches to AVX2 (x86_64) or NEON
    /// (aarch64) accelerated implementations; otherwise scalar.
    pub fn ntt(&mut self) {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        {
            crate::ntt_avx2::ntt_simd(&mut self.coeffs);
        }
        #[cfg(all(feature = "simd", target_arch = "aarch64"))]
        {
            crate::ntt_neon::ntt_simd(&mut self.coeffs);
        }
        #[cfg(not(all(feature = "simd", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        crate::ntt::ntt(&mut self.coeffs);
    }

    /// In-place inverse NTT with Montgomery factor.
    ///
    /// With the `simd` feature, dispatches to AVX2 (x86_64) or NEON
    /// (aarch64) accelerated implementations; otherwise scalar.
    pub fn invntt_tomont(&mut self) {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        {
            crate::ntt_avx2::invntt_simd(&mut self.coeffs);
        }
        #[cfg(all(feature = "simd", target_arch = "aarch64"))]
        {
            crate::ntt_neon::invntt_simd(&mut self.coeffs);
        }
        #[cfg(not(all(feature = "simd", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        crate::ntt::invntt_tomont(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain with Montgomery reduction.
    pub fn pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
        for i in 0..N {
            c.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
    }

    /// In-place pointwise multiplication: `r = a * r` (NTT domain).
    ///
    /// Avoids the caller having to clone `r`.
    pub fn pointwise_montgomery_assign(r: &mut Poly, a: &Poly) {
        for i in 0..N {
            r.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * r.coeffs[i] as i64);
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

    /// In-place hint application: `r = UseHint(h, r)`.
    ///
    /// Avoids the caller having to clone `r`.
    pub fn use_hint_assign(mode: DilithiumMode, r: &mut Poly, h: &Poly) {
        for i in 0..N {
            r.coeffs[i] = rounding::use_hint(mode, r.coeffs[i], h.coeffs[i] != 0);
        }
    }

    /// Check infinity norm against bound B.
    /// Returns `true` if norm >= B (i.e., check fails).
    ///
    /// # Constant time
    ///
    /// The scan is unconditional: unlike the C reference (which returns on
    /// the first out-of-bound coefficient), the running time does not depend
    /// on *which* coefficient — or how many — violate the bound. During
    /// signing this function is applied to the secret rejection candidates
    /// `z = y + c*s1`, `w0 - c*s2` and `c*t0`; the accept/reject decision is
    /// public, but the position of the first large coefficient is not.
    ///
    /// The `bound > (Q-1)/8` guard branches only on a public mode constant.
    #[must_use]
    pub fn chknorm(&self, bound: i32) -> bool {
        if bound > (Q - 1) / 8 {
            return true;
        }
        let mut fail = 0i32;
        for i in 0..N {
            let c = self.coeffs[i];
            // Branchless absolute value (handles the Q/2 boundary).
            let sign = c >> 31;
            let t = c.wrapping_sub(sign & c.wrapping_mul(2));
            // 1 iff t >= bound, i.e. iff bound - 1 - t is negative.
            fail |= ((bound.wrapping_sub(1).wrapping_sub(t)) >> 31) & 1;
        }
        fail != 0
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
    /// via rejection sampling on output of SHAKE128 (FIPS 204 `RejNTTPoly`).
    pub fn uniform(a: &mut Poly, seed: &[u8; SEEDBYTES], nonce: u16) {
        let mut stream = Stream128::init(seed, nonce);
        Self::uniform_from_stream(a, &mut stream);
    }

    /// `uniform` driven by an arbitrary XOF, so the refill path can be tested.
    ///
    /// Both 840 (the initial squeeze) and 168 (each refill) are multiples of
    /// 3, so no partial 3-byte group is ever straddled and the C reference's
    /// leftover-carry bookkeeping is unnecessary.
    pub fn uniform_from_stream<S: XofStream>(a: &mut Poly, stream: &mut S) {
        const NBLOCKS: usize = 768_usize.div_ceil(STREAM128_BLOCKBYTES);
        const BUFLEN: usize = NBLOCKS * STREAM128_BLOCKBYTES;

        let mut buf = [0u8; BUFLEN];
        stream.squeeze(&mut buf);

        let mut ctr = Self::rej_uniform(&mut a.coeffs[..N], &buf);

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
        let mut stream = Stream256::init(seed, nonce);
        Self::uniform_eta_from_stream(mode, a, &mut stream);
    }

    /// `uniform_eta` driven by an arbitrary XOF, so the refill path can be
    /// tested.
    ///
    /// The squeezed bytes *are* secret key material (`s1`, `s2`), so every
    /// buffer is zeroized before it goes out of scope.
    pub fn uniform_eta_from_stream<S: XofStream>(
        mode: DilithiumMode,
        a: &mut Poly,
        stream: &mut S,
    ) {
        let nblocks = if mode.eta() == 2 {
            136_usize.div_ceil(STREAM256_BLOCKBYTES)
        } else {
            227_usize.div_ceil(STREAM256_BLOCKBYTES)
        };

        let mut buf = vec![0u8; nblocks * STREAM256_BLOCKBYTES];
        stream.squeeze(&mut buf);

        let mut ctr = Self::rej_eta(mode, &mut a.coeffs[..N], &buf);
        buf.zeroize();
        while ctr < N {
            let mut tmp = [0u8; STREAM256_BLOCKBYTES];
            stream.squeeze(&mut tmp);
            ctr += Self::rej_eta(mode, &mut a.coeffs[ctr..N], &tmp);
            tmp.zeroize();
        }
    }

    /// Sample polynomial with coefficients in [-(GAMMA1-1), GAMMA1]
    /// by unpacking SHAKE256 stream output.
    ///
    /// The squeezed bytes are the packed form of the secret mask `y`, so the
    /// buffer is zeroized before it goes out of scope.
    pub fn uniform_gamma1(mode: DilithiumMode, a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
        let polyz_packed = mode.polyz_packedbytes();
        let nblocks = polyz_packed.div_ceil(STREAM256_BLOCKBYTES);

        let mut stream = Stream256::init(seed, nonce);
        let mut buf = vec![0u8; nblocks * STREAM256_BLOCKBYTES];
        stream.squeeze(&mut buf);

        Self::polyz_unpack(mode, a, &buf);
        buf.zeroize();
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
                t.zeroize(); // holds secret s1/s2 coefficients
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
        t.zeroize(); // holds secret t0 coefficients
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

    /// A stream whose first block is entirely `0xFF`: every 3-byte group
    /// masks to `0x7FFFFF >= Q`, so all 280 candidates are rejected and the
    /// refill loop in `uniform_from_stream` must run. That loop is
    /// unreachable in practice (p < 2^-100 with a real XOF) yet it is the
    /// path that keeps `RejNTTPoly` correct, so it is tested explicitly.
    struct RejectFirstBlock {
        emitted_rejects: bool,
        tail: alloc::vec::Vec<u8>,
        pos: usize,
    }

    impl RejectFirstBlock {
        fn new(tail_len: usize) -> Self {
            // Deterministic pseudorandom tail whose first group is 0x7FFFFF
            // (>= Q, rejected) so both arms of the acceptance test run.
            let mut tail = alloc::vec::Vec::with_capacity(tail_len);
            tail.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
            let mut x: u32 = 0x1234_5678;
            for _ in 3..tail_len {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                tail.push((x >> 16) as u8);
            }
            Self {
                emitted_rejects: false,
                tail,
                pos: 0,
            }
        }
    }

    impl crate::symmetric::XofStream for RejectFirstBlock {
        fn squeeze(&mut self, out: &mut [u8]) {
            if !self.emitted_rejects {
                self.emitted_rejects = true;
                out.fill(0xFF);
                return;
            }
            for b in out.iter_mut() {
                *b = self.tail[self.pos % self.tail.len()];
                self.pos += 1;
            }
        }
    }

    #[test]
    fn test_rej_uniform_rejects_out_of_range_candidates() {
        // 0x7FFFFF (all bits of the 23-bit window set) is >= Q.
        let buf = [0xFFu8; 30];
        let mut a = [0i32; 10];
        assert_eq!(Poly::rej_uniform(&mut a, &buf), 0);
        // A short buffer cannot complete a 3-byte group.
        assert_eq!(Poly::rej_uniform(&mut a, &[0u8; 2]), 0);
    }

    #[test]
    fn test_uniform_from_stream_refills_when_first_block_all_rejected() {
        let mut a = Poly::zero();
        let mut stream = RejectFirstBlock::new(4096);
        Poly::uniform_from_stream(&mut a, &mut stream);

        // Every coefficient must be a valid field element in [0, Q-1].
        assert!(a.coeffs.iter().all(|c| (0..Q).contains(c)));

        // Independently recompute the expected coefficients from the same
        // byte stream: the first (all-0xFF) block yields nothing, and every
        // refill block is a multiple of 3 bytes, so the accepted values are
        // exactly the in-range 23-bit groups of the concatenated tail.
        let mut expected = alloc::vec::Vec::new();
        {
            use crate::symmetric::XofStream;
            let mut feed = RejectFirstBlock::new(4096);
            let mut first = [0u8; 840];
            feed.squeeze(&mut first);
            while expected.len() < N {
                let mut block = [0u8; STREAM128_BLOCKBYTES];
                feed.squeeze(&mut block);
                for chunk in block.chunks_exact(3) {
                    let t = (chunk[0] as u32 | (chunk[1] as u32) << 8 | (chunk[2] as u32) << 16)
                        & 0x7FFFFF;
                    if t < Q as u32 {
                        expected.push(t as i32);
                    }
                }
            }
            expected.truncate(N);
        }
        assert_eq!(&a.coeffs[..], &expected[..]);
    }

    #[test]
    fn test_uniform_eta_from_stream_refills() {
        // One SHAKE256 block is 136 bytes = 272 half-byte candidates; with
        // eta=2 only values < 15 are accepted, so a block of 0xFF nibbles
        // (15) is fully rejected and forces the refill path.
        struct AllFifteenThenReal {
            first: bool,
            x: u32,
        }
        impl crate::symmetric::XofStream for AllFifteenThenReal {
            fn squeeze(&mut self, out: &mut [u8]) {
                if self.first {
                    self.first = false;
                    out.fill(0xFF); // both nibbles = 15 -> always rejected
                    return;
                }
                for b in out.iter_mut() {
                    self.x = self.x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    *b = (self.x >> 16) as u8;
                }
            }
        }

        for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
            let eta = mode.eta();
            let mut a = Poly::zero();
            let mut stream = AllFifteenThenReal { first: true, x: 7 };
            Poly::uniform_eta_from_stream(mode, &mut a, &mut stream);
            assert!(a.coeffs.iter().all(|c| c.abs() <= eta));
        }
    }

    #[test]
    fn test_chknorm_rejects_oversized_bound() {
        // A bound above (Q-1)/8 is always reported as a failure.
        let a = Poly::zero();
        assert!(a.chknorm((Q - 1) / 8 + 1));
        assert!(!a.chknorm((Q - 1) / 8));
    }

    #[test]
    fn test_chknorm_is_position_independent() {
        // The branchless scan must flag a violation wherever it sits.
        for pos in [0usize, 1, 127, 255] {
            let mut a = Poly::zero();
            a.coeffs[pos] = 1000;
            assert!(a.chknorm(1000));
            assert!(!a.chknorm(1001));
            let mut b = Poly::zero();
            b.coeffs[pos] = -1000;
            assert!(b.chknorm(1000));
            assert!(!b.chknorm(1001));
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
