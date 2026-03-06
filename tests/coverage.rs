//! Edge-case and full-coverage tests for dilithium-rs.

use dilithium::params::*;
use dilithium::safe_api::*;

// ================================================================
// Error Path Coverage
// ================================================================

#[test]
fn test_sign_ctx_boundary_255() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let ctx = vec![0u8; 255]; // max allowed
    let sig = kp.sign(b"msg", &ctx);
    assert!(sig.is_ok(), "ctx=255 should succeed");
}

#[test]
fn test_sign_ctx_boundary_256() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let ctx = vec![0u8; 256]; // 1 over max
    assert_eq!(
        kp.sign(b"msg", &ctx).unwrap_err(),
        DilithiumError::BadArgument
    );
}

#[test]
fn test_prehash_ctx_boundary_255() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let ctx = vec![0u8; 255];
    let sig = kp.sign_prehash(b"msg", &ctx);
    assert!(sig.is_ok(), "prehash ctx=255 should succeed");
}

#[test]
fn test_prehash_ctx_boundary_256() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let ctx = vec![0u8; 256];
    assert_eq!(
        kp.sign_prehash(b"msg", &ctx).unwrap_err(),
        DilithiumError::BadArgument
    );
}

// ================================================================
// Verify error paths
// ================================================================

#[test]
fn test_verify_wrong_pk_size() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let sig = kp.sign(b"msg", b"").unwrap();
    // Wrong pk size
    assert!(!DilithiumKeyPair::verify(
        &[0u8; 100],
        &sig,
        b"msg",
        b"",
        DilithiumMode::Dilithium2
    ));
}

#[test]
fn test_verify_wrong_sig_size() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let bad_sig = DilithiumSignature::from_bytes(vec![0u8; 100]);
    assert!(!DilithiumKeyPair::verify(
        kp.public_key(),
        &bad_sig,
        b"msg",
        b"",
        DilithiumMode::Dilithium2
    ));
}

#[test]
fn test_verify_prehash_wrong_pk_size() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let sig = kp.sign_prehash(b"msg", b"").unwrap();
    assert!(!DilithiumKeyPair::verify_prehash(
        &[0u8; 100],
        &sig,
        b"msg",
        b"",
        DilithiumMode::Dilithium2
    ));
}

// ================================================================
// Cross-mode rejection
// ================================================================

#[test]
fn test_cross_mode_rejection() {
    let kp2 = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let sig2 = kp2.sign(b"msg", b"").unwrap();

    // Dilithium2 sig should fail on Dilithium3 verify (different sizes)
    assert!(!DilithiumKeyPair::verify(
        kp2.public_key(),
        &sig2,
        b"msg",
        b"",
        DilithiumMode::Dilithium3
    ));
}

// ================================================================
// Key import validation
// ================================================================

#[test]
fn test_from_keys_mode_mismatch() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    // Try importing as Dilithium3 — wrong sizes
    let result =
        DilithiumKeyPair::from_keys(kp.private_key(), kp.public_key(), DilithiumMode::Dilithium3);
    assert_eq!(result.unwrap_err(), DilithiumError::FormatError);
}

#[test]
fn test_from_keys_roundtrip_all_modes() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let kp = DilithiumKeyPair::generate(mode).unwrap();
        let kp2 = DilithiumKeyPair::from_keys(kp.private_key(), kp.public_key(), mode).unwrap();
        assert_eq!(kp2.public_key(), kp.public_key());
        assert_eq!(kp2.private_key(), kp.private_key());
        assert_eq!(kp2.mode(), mode);
    }
}

// ================================================================
// Empty and large messages
// ================================================================

#[test]
fn test_sign_empty_message() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let sig = kp.sign(b"", b"").unwrap();
    assert!(DilithiumKeyPair::verify(
        kp.public_key(),
        &sig,
        b"",
        b"",
        DilithiumMode::Dilithium2
    ));
}

#[test]
fn test_sign_large_message() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let msg = vec![0xAB; 10_000];
    let sig = kp.sign(&msg, b"").unwrap();
    assert!(DilithiumKeyPair::verify(
        kp.public_key(),
        &sig,
        &msg,
        b"",
        DilithiumMode::Dilithium2
    ));
}

// ================================================================
// Deterministic keygen consistency
// ================================================================

#[test]
fn test_deterministic_keygen_all_modes() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let seed = [0x42u8; 32];
        let kp1 = DilithiumKeyPair::generate_deterministic(mode, &seed);
        let kp2 = DilithiumKeyPair::generate_deterministic(mode, &seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.private_key(), kp2.private_key());

        // Different seed → different keys
        let seed2 = [0x43u8; 32];
        let kp3 = DilithiumKeyPair::generate_deterministic(mode, &seed2);
        assert_ne!(kp3.public_key(), kp1.public_key());
    }
}

// ================================================================
// Deterministic signing consistency
// ================================================================

#[test]
fn test_deterministic_signing() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[0u8; 32]);
    let rnd = [0u8; 32];
    let sig1 = kp.sign_deterministic(b"msg", b"ctx", &rnd).unwrap();
    let sig2 = kp.sign_deterministic(b"msg", b"ctx", &rnd).unwrap();
    assert_eq!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "deterministic signing should be reproducible"
    );
}

// ================================================================
// Signature bytes round-trip
// ================================================================

#[test]
fn test_signature_from_bytes_roundtrip() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let sig = kp.sign(b"msg", b"").unwrap();
    let sig_bytes = sig.as_bytes().to_vec();
    let sig2 = DilithiumSignature::from_bytes(sig_bytes);
    assert!(DilithiumKeyPair::verify(
        kp.public_key(),
        &sig2,
        b"msg",
        b"",
        DilithiumMode::Dilithium2
    ));
}

// ================================================================
// FIPS name and OID coverage
// ================================================================

#[test]
fn test_hash_oid_lengths() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let oid = mode.hash_oid();
        assert_eq!(oid.len(), 11, "OID should be 11 bytes (DER-encoded)");
        assert_eq!(oid[0], 0x06, "OID should start with 0x06");
    }
}

#[test]
fn test_all_mode_sizes_match_fips() {
    // FIPS 204 Table 1
    assert_eq!(ML_DSA_44.public_key_bytes(), 1312);
    assert_eq!(ML_DSA_44.secret_key_bytes(), 2560);
    assert_eq!(ML_DSA_44.signature_bytes(), 2420);

    assert_eq!(ML_DSA_65.public_key_bytes(), 1952);
    assert_eq!(ML_DSA_65.secret_key_bytes(), 4032);
    assert_eq!(ML_DSA_65.signature_bytes(), 3309);

    assert_eq!(ML_DSA_87.public_key_bytes(), 2592);
    assert_eq!(ML_DSA_87.secret_key_bytes(), 4896);
    assert_eq!(ML_DSA_87.signature_bytes(), 4627);
}
