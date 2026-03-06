//! NIST KAT vector validation test.
//!
//! Replicates the deterministic SHAKE128-based RNG from the C reference's
//! `test_vectors.c` to generate the same keypair, sign the same message,
//! and verify the pk/sk/sig SHAKE256 hashes match bit-for-bit.
//!
//! The C reference uses `snprintf(ctx, 13, "test_vectors")` producing a
//! 13-byte context string that includes the null terminator.

use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake128;

use dilithium::params::*;
use dilithium::sign;
use dilithium::symmetric::shake256;

/// Deterministic RNG matching the C reference's test_vectors.c.
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

/// C reference context: "test_vectors\0" (13 bytes including null terminator)
const C_CTX: &[u8; 13] = b"test_vectors\0";

/// C reference expected values for Dilithium2 count=0, deterministic signing (rnd=0).
const D2_M: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
const D2_PK_HASH: &str = "030116e37de6921adade6bbe80ea940ca24ff5a51153ed0f52c40873f947b9d6";
const D2_SK_HASH: &str = "798e76ae4ac99e7cb6c3aa4b62951fd9b71b8d86eade71baee5742199e1cef01";
const D2_SIG_HASH: &str = "f4365abfc7518dce6d2323ca21760dd8c36b10710349fd6fe25e1043d999bb60";

#[test]
fn test_kat_dilithium2_keygen() {
    let mode = DilithiumMode::Dilithium2;
    let mut rng = DeterministicRng::new();

    let mut m = [0u8; 32];
    rng.fill(&mut m);
    assert_eq!(bytes_to_hex(&m), D2_M, "RNG message mismatch");

    let mut seed = [0u8; SEEDBYTES];
    rng.fill(&mut seed);
    let (pk, sk) = sign::keypair(mode, &seed);

    let mut pk_hash = [0u8; 32];
    shake256(&mut pk_hash, &pk);
    assert_eq!(
        bytes_to_hex(&pk_hash),
        D2_PK_HASH,
        "Public key hash mismatch — keygen diverged from C reference"
    );

    let mut sk_hash = [0u8; 32];
    shake256(&mut sk_hash, &sk);
    assert_eq!(
        bytes_to_hex(&sk_hash),
        D2_SK_HASH,
        "Secret key hash mismatch — keygen diverged from C reference"
    );
}

#[test]
fn test_kat_dilithium2_sign_deterministic() {
    let mode = DilithiumMode::Dilithium2;
    let mut rng = DeterministicRng::new();

    let mut m = [0u8; 32];
    rng.fill(&mut m);
    let mut seed = [0u8; SEEDBYTES];
    rng.fill(&mut seed);
    let (pk, sk) = sign::keypair(mode, &seed);

    // Deterministic signing: rnd=0, ctx includes null terminator (C convention)
    let rnd = [0u8; RNDBYTES];
    let mut sig = vec![0u8; mode.signature_bytes()];
    sign::sign_signature(mode, &mut sig, &m, C_CTX, &rnd, &sk);

    let mut sig_hash = [0u8; 32];
    shake256(&mut sig_hash, &sig);
    assert_eq!(
        bytes_to_hex(&sig_hash),
        D2_SIG_HASH,
        "Signature hash mismatch — signing diverged from C reference"
    );

    // Verify signature
    assert!(
        sign::verify(mode, &sig, &m, C_CTX, &pk),
        "KAT signature verification failed"
    );
}
