//! SHAKE128 / SHAKE256 with a zeroizable sponge state.
//!
//! Dilithium derives every secret from a SHAKE stream: `s1`/`s2` from `rho'`
//! in key generation, the mask `y` from `rho'` on every signing iteration,
//! and `rho'` itself from the long-term key `K`. The absorbed and permuted
//! Keccak state therefore holds secret-derived material for as long as the
//! XOF object lives.
//!
//! The `sha3` crate does not expose its state and (as of 0.10) has no
//! `zeroize` support, so this module implements the sponge directly on top of
//! the `keccak` permutation — the same primitive `sha3` uses — and wipes the
//! state on drop.
//!
//! Correctness is pinned against the `sha3` crate in the tests below, at and
//! around every rate boundary, in addition to the FIPS 204 KAT and ACVP
//! suites that exercise it end to end.

use zeroize::Zeroize;

/// Rate (block size) of SHAKE128 in bytes: `(1600 - 2*128) / 8`.
pub const SHAKE128_RATE: usize = 168;
/// Rate (block size) of SHAKE256 in bytes: `(1600 - 2*256) / 8`.
pub const SHAKE256_RATE: usize = 136;

/// Keccak-f\[1600\] sponge in SHAKE (0x1F padding) mode.
///
/// `RATE` must be a positive multiple of 8 and at most 200; both SHAKE rates
/// are (168 = 21 lanes, 136 = 17 lanes).
pub struct Shake<const RATE: usize> {
    state: [u64; 25],
    /// Byte offset into the current rate block.
    pos: usize,
    squeezing: bool,
}

const _: () = assert!(SHAKE128_RATE % 8 == 0 && SHAKE128_RATE < 200);
const _: () = assert!(SHAKE256_RATE % 8 == 0 && SHAKE256_RATE < 200);

impl<const RATE: usize> Default for Shake<RATE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RATE: usize> Shake<RATE> {
    /// Number of 64-bit lanes covered by the rate.
    const LANES: usize = RATE / 8;

    /// Create an empty sponge.
    ///
    /// # Panics
    ///
    /// Panics if `RATE` is not a positive multiple of 8 below 200. The check
    /// is constant-folded away for the two rates this crate instantiates.
    #[must_use]
    pub const fn new() -> Self {
        assert!(
            RATE > 0 && RATE % 8 == 0 && RATE < 200,
            "RATE must be a positive multiple of 8 below the 200-byte state"
        );
        Self {
            state: [0u64; 25],
            pos: 0,
            squeezing: false,
        }
    }

    #[inline]
    fn xor_byte(&mut self, offset: usize, b: u8) {
        self.state[offset / 8] ^= u64::from(b) << (8 * (offset % 8));
    }

    #[inline]
    fn read_byte(&self, offset: usize) -> u8 {
        (self.state[offset / 8] >> (8 * (offset % 8))) as u8
    }

    /// Absorb input. May be called repeatedly before the first squeeze.
    ///
    /// # Panics
    ///
    /// Panics if called after squeezing has started (a programming error:
    /// SHAKE has no absorb-after-squeeze mode).
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "absorb after squeeze");
        let mut data = data;

        while !data.is_empty() {
            // Fast path: a whole aligned block XORs lane-wise.
            if self.pos == 0 && data.len() >= RATE {
                for lane in 0..Self::LANES {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[8 * lane..8 * lane + 8]);
                    self.state[lane] ^= u64::from_le_bytes(bytes);
                }
                keccak::f1600(&mut self.state);
                data = &data[RATE..];
                continue;
            }

            let take = core::cmp::min(RATE - self.pos, data.len());
            for (i, &b) in data[..take].iter().enumerate() {
                self.xor_byte(self.pos + i, b);
            }
            self.pos += take;
            data = &data[take..];
            if self.pos == RATE {
                keccak::f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Apply the SHAKE padding `0x1F … 0x80` and switch to squeezing.
    fn finalize(&mut self) {
        debug_assert!(!self.squeezing);
        self.xor_byte(self.pos, 0x1F);
        self.xor_byte(RATE - 1, 0x80);
        keccak::f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Squeeze output. May be called repeatedly; the stream continues.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.finalize();
        }
        let mut out = out;

        while !out.is_empty() {
            if self.pos == RATE {
                keccak::f1600(&mut self.state);
                self.pos = 0;
            }

            // Fast path: a whole aligned block is written lane-wise.
            if self.pos == 0 && out.len() >= RATE {
                for lane in 0..Self::LANES {
                    out[8 * lane..8 * lane + 8].copy_from_slice(&self.state[lane].to_le_bytes());
                }
                self.pos = RATE;
                out = &mut out[RATE..];
                continue;
            }

            let take = core::cmp::min(RATE - self.pos, out.len());
            for i in 0..take {
                out[i] = self.read_byte(self.pos + i);
            }
            self.pos += take;
            out = &mut out[take..];
        }
    }
}

impl<const RATE: usize> Zeroize for Shake<RATE> {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.pos = 0;
        self.squeezing = false;
    }
}

/// The sponge state is secret-derived in most of its uses, so it is wiped
/// unconditionally when the object goes out of scope.
impl<const RATE: usize> Drop for Shake<RATE> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHAKE128 sponge (rate 168 bytes).
pub type Shake128 = Shake<SHAKE128_RATE>;
/// SHAKE256 sponge (rate 136 bytes).
pub type Shake256 = Shake<SHAKE256_RATE>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    fn reference_shake128(input: &[u8], outlen: usize) -> Vec<u8> {
        let mut h = sha3::Shake128::default();
        h.update(input);
        let mut r = h.finalize_xof();
        let mut out = vec![0u8; outlen];
        r.read(&mut out);
        out
    }

    fn reference_shake256(input: &[u8], outlen: usize) -> Vec<u8> {
        let mut h = sha3::Shake256::default();
        h.update(input);
        let mut r = h.finalize_xof();
        let mut out = vec![0u8; outlen];
        r.read(&mut out);
        out
    }

    /// Input and output lengths around every rate boundary, plus the empty
    /// input and multi-block squeezes.
    fn boundary_lengths(rate: usize) -> Vec<usize> {
        let mut v = vec![0usize, 1, 2, 7, 8, 9, 63, 64, 65];
        for k in 1..=3 {
            let b = rate * k;
            v.extend_from_slice(&[b - 2, b - 1, b, b + 1, b + 2]);
        }
        v.push(rate * 4 + 7);
        v
    }

    #[test]
    fn shake128_matches_sha3_crate() {
        for &inlen in &boundary_lengths(SHAKE128_RATE) {
            let input: Vec<u8> = (0..inlen).map(|i| (i * 7 + 3) as u8).collect();
            for &outlen in &boundary_lengths(SHAKE128_RATE) {
                let mut got = vec![0u8; outlen];
                let mut s = Shake128::new();
                s.absorb(&input);
                s.squeeze(&mut got);
                assert_eq!(
                    got,
                    reference_shake128(&input, outlen),
                    "SHAKE128 mismatch inlen={inlen} outlen={outlen}"
                );
            }
        }
    }

    #[test]
    fn shake256_matches_sha3_crate() {
        for &inlen in &boundary_lengths(SHAKE256_RATE) {
            let input: Vec<u8> = (0..inlen).map(|i| (i * 11 + 5) as u8).collect();
            for &outlen in &boundary_lengths(SHAKE256_RATE) {
                let mut got = vec![0u8; outlen];
                let mut s = Shake256::new();
                s.absorb(&input);
                s.squeeze(&mut got);
                assert_eq!(
                    got,
                    reference_shake256(&input, outlen),
                    "SHAKE256 mismatch inlen={inlen} outlen={outlen}"
                );
            }
        }
    }

    /// Split absorbs must equal one contiguous absorb (the signing path
    /// absorbs `key`, `rnd` and `mu` separately).
    #[test]
    fn split_absorb_matches_contiguous() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for split in [
            0usize, 1, 7, 8, 135, 136, 137, 167, 168, 169, 500, 999, 1000,
        ] {
            let (a, b) = data.split_at(split);
            let mut s = Shake256::new();
            s.absorb(a);
            s.absorb(b);
            let mut got = [0u8; 200];
            s.squeeze(&mut got);
            assert_eq!(
                got.to_vec(),
                reference_shake256(&data, 200),
                "split absorb at {split}"
            );
        }
    }

    /// Split squeezes must equal one contiguous squeeze (rejection sampling
    /// tops up one block at a time).
    #[test]
    fn split_squeeze_matches_contiguous() {
        let input = b"dilithium shake split squeeze";
        let want = reference_shake128(input, 1000);
        for chunk in [1usize, 7, 8, 100, 167, 168, 169, 336, 500] {
            let mut s = Shake128::new();
            s.absorb(input);
            let mut got = Vec::new();
            while got.len() < 1000 {
                let take = core::cmp::min(chunk, 1000 - got.len());
                let mut buf = vec![0u8; take];
                s.squeeze(&mut buf);
                got.extend_from_slice(&buf);
            }
            assert_eq!(got, want, "split squeeze in chunks of {chunk}");
        }
    }

    /// Zeroize must clear the whole sponge, and it must be usable again.
    #[test]
    fn zeroize_clears_state() {
        let mut s = Shake256::new();
        s.absorb(b"secret");
        let mut out = [0u8; 32];
        s.squeeze(&mut out);
        assert!(s.state.iter().any(|&l| l != 0));

        s.zeroize();
        assert!(s.state.iter().all(|&l| l == 0));
        assert_eq!(s.pos, 0);
        assert!(!s.squeezing);

        // A zeroized sponge behaves like a fresh one.
        s.absorb(b"again");
        let mut a = [0u8; 32];
        s.squeeze(&mut a);
        let mut fresh = Shake256::new();
        fresh.absorb(b"again");
        let mut b = [0u8; 32];
        fresh.squeeze(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn default_matches_new() {
        let mut a = Shake256::default();
        let mut b = Shake256::new();
        a.absorb(b"x");
        b.absorb(b"x");
        let mut oa = [0u8; 16];
        let mut ob = [0u8; 16];
        a.squeeze(&mut oa);
        b.squeeze(&mut ob);
        assert_eq!(oa, ob);

        let mut c = Shake128::default();
        c.absorb(b"x");
        let mut oc = [0u8; 16];
        c.squeeze(&mut oc);
        assert_eq!(oc.to_vec(), reference_shake128(b"x", 16));
    }

    #[test]
    #[should_panic(expected = "absorb after squeeze")]
    fn absorb_after_squeeze_panics() {
        let mut s = Shake256::new();
        let mut out = [0u8; 8];
        s.squeeze(&mut out);
        s.absorb(b"too late");
    }
}
