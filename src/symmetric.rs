//! SHAKE-based symmetric primitives for Dilithium.
//!
//! Provides the stream initialization of `symmetric-shake.c` from the
//! reference implementation, on top of the zeroizing sponge in
//! [`crate::shake`]. `no_std` + WASM compatible.
//!
//! Every state here is wiped on drop, because in Dilithium most of them are
//! seeded with secret material: `Stream256` is initialized from `rho'`
//! (ExpandS, ExpandMask) and the incremental state absorbs the long-term key
//! `K` when deriving `rho'`.

use crate::params::{CRHBYTES, SEEDBYTES};
use crate::shake::{Shake128, Shake256};

/// A squeezable extendable-output byte source.
///
/// Abstracting the XOF behind a trait lets the rejection-sampling refill
/// loops in [`crate::poly`] be driven by a deterministic test stream, so the
/// (in practice astronomically unlikely, but security-relevant) "one SHAKE
/// block was not enough" path can actually be exercised. Monomorphized —
/// no runtime cost over calling the concrete type.
pub trait XofStream {
    /// Squeeze `out.len()` bytes from the stream.
    fn squeeze(&mut self, out: &mut [u8]);
}

/// SHAKE128 stream state.
pub struct Stream128 {
    sponge: Shake128,
}

impl Stream128 {
    /// Initialize SHAKE128 stream: absorb `seed || le16(nonce)`.
    #[must_use]
    pub fn init(seed: &[u8; SEEDBYTES], nonce: u16) -> Self {
        let mut sponge = Shake128::new();
        sponge.absorb(seed);
        sponge.absorb(&nonce.to_le_bytes());
        Self { sponge }
    }

    /// Squeeze bytes from the stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out);
    }
}

impl XofStream for Stream128 {
    #[inline]
    fn squeeze(&mut self, out: &mut [u8]) {
        Stream128::squeeze(self, out);
    }
}

/// SHAKE256 stream state.
pub struct Stream256 {
    sponge: Shake256,
}

impl Stream256 {
    /// Initialize SHAKE256 stream: absorb `seed || le16(nonce)`.
    #[must_use]
    pub fn init(seed: &[u8; CRHBYTES], nonce: u16) -> Self {
        let mut sponge = Shake256::new();
        sponge.absorb(seed);
        sponge.absorb(&nonce.to_le_bytes());
        Self { sponge }
    }

    /// Squeeze bytes from the stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out);
    }
}

impl XofStream for Stream256 {
    #[inline]
    fn squeeze(&mut self, out: &mut [u8]) {
        Stream256::squeeze(self, out);
    }
}

/// Compute SHAKE256(input) and write to `output`.
pub fn shake256(output: &mut [u8], input: &[u8]) {
    let mut sponge = Shake256::new();
    sponge.absorb(input);
    sponge.squeeze(output);
}

/// Incremental SHAKE256 state for multi-absorb patterns.
pub struct Shake256State {
    sponge: Shake256,
}

/// SHAKE256 XOF reader after finalization.
pub struct Shake256Reader {
    sponge: Shake256,
}

impl Shake256State {
    /// Create new SHAKE256 state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sponge: Shake256::new(),
        }
    }

    /// Absorb data.
    pub fn absorb(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    /// Finalize and return reader for squeezing.
    #[must_use]
    pub fn finalize(self) -> Shake256Reader {
        Shake256Reader {
            sponge: self.sponge,
        }
    }
}

impl Default for Shake256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256Reader {
    /// Squeeze bytes.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out);
    }
}

/// Multi-part SHAKE256: absorb multiple slices, squeeze output.
/// Used for `H(rho, t1)` => `tr`, and `CRH(tr, pre, msg)` => `mu`, etc.
pub fn shake256_multi(output: &mut [u8], inputs: &[&[u8]]) {
    let mut sponge = Shake256::new();
    for input in inputs {
        sponge.absorb(input);
    }
    sponge.squeeze(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_deterministic() {
        let input = b"test input";
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        shake256(&mut out1, input);
        shake256(&mut out2, input);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake256_different_inputs() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        shake256(&mut out1, b"hello");
        shake256(&mut out2, b"world");
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_stream128_deterministic() {
        let seed = [0u8; SEEDBYTES];
        let mut s1 = Stream128::init(&seed, 0);
        let mut s2 = Stream128::init(&seed, 0);
        let mut b1 = [0u8; 64];
        let mut b2 = [0u8; 64];
        s1.squeeze(&mut b1);
        s2.squeeze(&mut b2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_stream256_deterministic() {
        let seed = [0u8; CRHBYTES];
        let mut s1 = Stream256::init(&seed, 0);
        let mut s2 = Stream256::init(&seed, 0);
        let mut b1 = [0u8; 64];
        let mut b2 = [0u8; 64];
        s1.squeeze(&mut b1);
        s2.squeeze(&mut b2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_shake256_multi() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        // Multi-part should give same result as single-part with concatenated input
        shake256_multi(&mut out1, &[b"hello", b"world"]);
        shake256(&mut out2, b"helloworld");
        assert_eq!(out1, out2);
    }
}
