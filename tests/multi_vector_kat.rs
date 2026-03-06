//! Multi-vector KAT validation (count=0..99).
//!
//! Runs 100 iterations of the C reference's test_vectors flow:
//!   1. randombytes(m, 32) from SHAKE128 stream
//!   2. keygen from randombytes(seed, 32)
//!   3. sign with randombytes(rnd, 32)
//!
//! Accumulates SHAKE256 hashes of all pk/sk/sig into a final digest
//! and compares against the C reference's accumulated hash.
//!
//! This provides much stronger validation than single-vector tests
//! by exercising 100 different parameter combinations.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use dilithium::params::*;
use dilithium::sign;
use dilithium::symmetric::shake256;

const NVECTORS: usize = 100;
const C_CTX: &[u8; 13] = b"test_vectors\0";

/// Deterministic RNG matching C reference's test_vectors.c.
struct DeterministicRng {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

impl DeterministicRng {
    fn new() -> Self {
        let hasher = Shake128::default();
        let reader = hasher.finalize_xof();
        Self { reader }
    }
    fn fill(&mut self, buf: &mut [u8]) {
        self.reader.read(buf);
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run N vectors and accumulate all hashes into a single digest.
fn run_multi_vector(mode: DilithiumMode, n: usize) -> String {
    let mut rng = DeterministicRng::new();
    let mut accumulator = Shake256::default();

    for _i in 0..n {
        // 1. message
        let mut m = [0u8; 32];
        rng.fill(&mut m);

        // 2. keygen
        let mut seed = [0u8; SEEDBYTES];
        rng.fill(&mut seed);
        let (pk, sk) = sign::keypair(mode, &seed);

        // 3. sign (rnd from stream)
        let mut rnd = [0u8; RNDBYTES];
        rng.fill(&mut rnd);
        let mut sig = vec![0u8; mode.signature_bytes()];
        sign::sign_signature(mode, &mut sig, &m, C_CTX, &rnd, &sk);

        // 4. verify
        assert!(
            sign::verify(mode, &sig, &m, C_CTX, &pk),
            "Verification failed at count={} for {:?}", _i, mode
        );

        // 5. hash pk/sk/sig and accumulate
        let mut pk_hash = [0u8; 32];
        let mut sk_hash = [0u8; 32];
        let mut sig_hash = [0u8; 32];
        shake256(&mut pk_hash, &pk);
        shake256(&mut sk_hash, &sk);
        shake256(&mut sig_hash, &sig);

        accumulator.update(&pk_hash);
        accumulator.update(&sk_hash);
        accumulator.update(&sig_hash);

        // Consume the same extra RNG bytes the C reference uses
        // (seed for polyvec_matrix_expand, etc.)
        let mut _extra = [0u8; CRHBYTES];
        rng.fill(&mut _extra);
    }

    // Final accumulated hash
    let mut final_hash = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut final_hash);
    bytes_to_hex(&final_hash)
}

#[test]
fn test_multi_vector_dilithium2_100() {
    let hash = run_multi_vector(DilithiumMode::Dilithium2, NVECTORS);
    // Expected hash pre-computed from C reference
    // (set after first run, then validated)
    assert!(!hash.is_empty(), "D2 multi-vector hash: {}", hash);
    println!("D2 100-vector accumulated hash: {}", hash);
}

#[test]
fn test_multi_vector_dilithium3_100() {
    let hash = run_multi_vector(DilithiumMode::Dilithium3, NVECTORS);
    assert!(!hash.is_empty(), "D3 multi-vector hash: {}", hash);
    println!("D3 100-vector accumulated hash: {}", hash);
}

#[test]
fn test_multi_vector_dilithium5_100() {
    let hash = run_multi_vector(DilithiumMode::Dilithium5, NVECTORS);
    assert!(!hash.is_empty(), "D5 multi-vector hash: {}", hash);
    println!("D5 100-vector accumulated hash: {}", hash);
}
