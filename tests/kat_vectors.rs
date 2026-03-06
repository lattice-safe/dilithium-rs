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

/// Dilithium3 (ML-DSA-65) expected values.
const D3_PK_HASH: &str = "b1043ca0ab60b411fbb1bf6fcc852fd54ee1339d90e877b5b032c3b3d0f167e2";
const D3_SK_HASH: &str = "320e90c853d708e52b91dc57d29f75fb63b82a1261c1eb491ce5cd1397d872aa";
const D3_SIG_HASH: &str = "693f19fedc793bbaec06c0736b9f1bd7fe29efa87063a3899f461eef4bf644b0";

/// Dilithium5 (ML-DSA-87) expected values.
const D5_PK_HASH: &str = "39f5d1b3e15e1d0d5d26571140e5f9d63e6a128751f0581756d9144264328d2f";
const D5_SK_HASH: &str = "d61328c2ec6eb79eb45990fc95f749fd7834c9e4b44f28bc934b894ed8ebd0dc";
const D5_SIG_HASH: &str = "a38389b0e4b72996268d3cb0b65b178f52feb3b5678fd04df0a9c0d05d56748d";

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

/// Helper to run a full KAT (keygen + sign + verify) for any mode.
fn run_kat_full(
    mode: DilithiumMode,
    expected_pk: &str,
    expected_sk: &str,
    expected_sig: &str,
) {
    let mut rng = DeterministicRng::new();

    let mut m = [0u8; 32];
    rng.fill(&mut m);
    let mut seed = [0u8; SEEDBYTES];
    rng.fill(&mut seed);
    let (pk, sk) = sign::keypair(mode, &seed);

    let mut pk_hash = [0u8; 32];
    shake256(&mut pk_hash, &pk);
    assert_eq!(
        bytes_to_hex(&pk_hash), expected_pk,
        "{:?}: public key hash mismatch", mode
    );

    let mut sk_hash = [0u8; 32];
    shake256(&mut sk_hash, &sk);
    assert_eq!(
        bytes_to_hex(&sk_hash), expected_sk,
        "{:?}: secret key hash mismatch", mode
    );

    let rnd = [0u8; RNDBYTES];
    let mut sig = vec![0u8; mode.signature_bytes()];
    sign::sign_signature(mode, &mut sig, &m, C_CTX, &rnd, &sk);

    let mut sig_hash = [0u8; 32];
    shake256(&mut sig_hash, &sig);
    assert_eq!(
        bytes_to_hex(&sig_hash), expected_sig,
        "{:?}: signature hash mismatch", mode
    );

    assert!(
        sign::verify(mode, &sig, &m, C_CTX, &pk),
        "{:?}: KAT signature verification failed", mode
    );
}

#[test]
fn test_kat_dilithium3_full() {
    run_kat_full(
        DilithiumMode::Dilithium3,
        D3_PK_HASH, D3_SK_HASH, D3_SIG_HASH,
    );
}

#[test]
fn test_kat_dilithium5_full() {
    run_kat_full(
        DilithiumMode::Dilithium5,
        D5_PK_HASH, D5_SK_HASH, D5_SIG_HASH,
    );
}

