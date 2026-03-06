//! SHAKE-based symmetric primitives for Dilithium.
//!
//! Wraps the `sha3` crate to provide the stream initialization
//! matching `symmetric-shake.c` from the reference implementation.
//! Designed for `no_std` + WASM compatibility.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::params::{CRHBYTES, SEEDBYTES};

/// SHAKE128 stream state.
pub struct Stream128 {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

impl Stream128 {
    /// Initialize SHAKE128 stream: absorb `seed || le16(nonce)`.
    #[must_use]
    pub fn init(seed: &[u8; SEEDBYTES], nonce: u16) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(seed);
        hasher.update(&nonce.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze bytes from the stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// SHAKE256 stream state.
pub struct Stream256 {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl Stream256 {
    /// Initialize SHAKE256 stream: absorb `seed || le16(nonce)`.
    #[must_use]
    pub fn init(seed: &[u8; CRHBYTES], nonce: u16) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&nonce.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze bytes from the stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// Compute SHAKE256(input) and write to `output`.
pub fn shake256(output: &mut [u8], input: &[u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// Incremental SHAKE256 state for multi-absorb patterns.
pub struct Shake256State {
    hasher: Shake256,
}

/// SHAKE256 XOF reader after finalization.
pub struct Shake256Reader {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl Shake256State {
    /// Create new SHAKE256 state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Shake256::default(),
        }
    }

    /// Absorb data.
    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return reader for squeezing.
    #[must_use]
    pub fn finalize(self) -> Shake256Reader {
        Shake256Reader {
            reader: self.hasher.finalize_xof(),
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
        self.reader.read(out);
    }
}

/// Multi-part SHAKE256: absorb multiple slices, squeeze output.
/// Used for `H(rho, t1)` => `tr`, and `CRH(tr, pre, msg)` => `mu`, etc.
pub fn shake256_multi(output: &mut [u8], inputs: &[&[u8]]) {
    let mut state = Shake256State::new();
    for input in inputs {
        state.absorb(input);
    }
    let mut reader = state.finalize();
    reader.squeeze(output);
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
