//! Round-trip integration tests for ML-DSA (FIPS 204).

use dilithium::safe_api::{DilithiumKeyPair, DilithiumMode};
use dilithium::{MlDsaKeyPair, ML_DSA_44, ML_DSA_65, ML_DSA_87};

// ================================================================
// Pure ML-DSA (§6.1) Tests
// ================================================================

#[test]
fn test_dilithium2_round_trip() {
    round_trip_test(DilithiumMode::Dilithium2);
}

#[test]
fn test_dilithium3_round_trip() {
    round_trip_test(DilithiumMode::Dilithium3);
}

#[test]
fn test_dilithium5_round_trip() {
    round_trip_test(DilithiumMode::Dilithium5);
}

fn round_trip_test(mode: DilithiumMode) {
    let iterations = 10;
    let msg = b"Test message for Dilithium signature verification";
    let ctx = b"test_context";

    for i in 0..iterations {
        let kp = DilithiumKeyPair::generate(mode).expect("keygen failed");

        assert_eq!(kp.public_key().len(), mode.public_key_bytes());

        let sig = kp.sign(msg, ctx).expect("sign failed");
        assert_eq!(sig.as_bytes().len(), mode.signature_bytes());

        assert!(
            DilithiumKeyPair::verify(kp.public_key(), &sig, msg, ctx, mode),
            "valid signature failed verification on iteration {}",
            i
        );

        assert!(
            !DilithiumKeyPair::verify(kp.public_key(), &sig, b"wrong message", ctx, mode),
            "wrong message should fail verification"
        );

        let mut bad_sig = sig.as_bytes().to_vec();
        if !bad_sig.is_empty() {
            bad_sig[0] ^= 0xFF;
            let bad = dilithium::DilithiumSignature::from_bytes(bad_sig);
            assert!(
                !DilithiumKeyPair::verify(kp.public_key(), &bad, msg, ctx, mode),
                "corrupted signature should fail verification on iteration {}",
                i
            );
        }
    }
}

// ================================================================
// ML-DSA naming aliases (FIPS 204 naming)
// ================================================================

#[test]
fn test_ml_dsa_naming() {
    // Aliases should work identically
    let kp = MlDsaKeyPair::generate(ML_DSA_44).expect("keygen failed");
    let sig = kp.sign(b"hello", b"").expect("sign failed");
    assert!(MlDsaKeyPair::verify(
        kp.public_key(),
        &sig,
        b"hello",
        b"",
        ML_DSA_44
    ));
}

#[test]
fn test_ml_dsa_65_alias() {
    assert_eq!(ML_DSA_65, DilithiumMode::Dilithium3);
}

#[test]
fn test_ml_dsa_87_alias() {
    assert_eq!(ML_DSA_87, DilithiumMode::Dilithium5);
}

#[test]
fn test_fips_names() {
    assert_eq!(DilithiumMode::Dilithium2.fips_name(), "ML-DSA-44");
    assert_eq!(DilithiumMode::Dilithium3.fips_name(), "ML-DSA-65");
    assert_eq!(DilithiumMode::Dilithium5.fips_name(), "ML-DSA-87");
}

// ================================================================
// HashML-DSA (§6.2) Tests
// ================================================================

#[test]
fn test_hash_ml_dsa_44_round_trip() {
    hash_round_trip_test(DilithiumMode::Dilithium2);
}

#[test]
fn test_hash_ml_dsa_65_round_trip() {
    hash_round_trip_test(DilithiumMode::Dilithium3);
}

#[test]
fn test_hash_ml_dsa_87_round_trip() {
    hash_round_trip_test(DilithiumMode::Dilithium5);
}

fn hash_round_trip_test(mode: DilithiumMode) {
    let kp = DilithiumKeyPair::generate(mode).expect("keygen failed");
    let msg = b"HashML-DSA prehash test message";
    let ctx = b"ctx";

    let sig = kp.sign_prehash(msg, ctx).expect("hash sign failed");
    assert_eq!(sig.as_bytes().len(), mode.signature_bytes());

    // Verify with prehash
    assert!(
        DilithiumKeyPair::verify_prehash(kp.public_key(), &sig, msg, ctx, mode),
        "HashML-DSA verification failed"
    );

    // Cross-mode: prehash sig should NOT verify with pure verify
    assert!(
        !DilithiumKeyPair::verify(kp.public_key(), &sig, msg, ctx, mode),
        "HashML-DSA sig should not pass pure ML-DSA verify"
    );

    // Wrong message should fail
    assert!(
        !DilithiumKeyPair::verify_prehash(kp.public_key(), &sig, b"wrong", ctx, mode),
        "Wrong message should fail HashML-DSA verify"
    );
}

// ================================================================
// Key validation (§7.1) Tests
// ================================================================

#[test]
fn test_key_validation_valid() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).expect("keygen failed");
    let result =
        DilithiumKeyPair::from_keys(kp.private_key(), kp.public_key(), DilithiumMode::Dilithium2);
    assert!(result.is_ok());
}

#[test]
fn test_key_validation_wrong_size() {
    let result = DilithiumKeyPair::from_keys(&[0u8; 100], &[0u8; 100], DilithiumMode::Dilithium2);
    assert_eq!(result.unwrap_err(), dilithium::DilithiumError::FormatError);
}

#[test]
fn test_key_validation_rho_mismatch() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).expect("keygen failed");
    let mut bad_pk = kp.public_key().to_vec();
    bad_pk[0] ^= 0xFF; // corrupt rho in pk
    let result = DilithiumKeyPair::from_keys(kp.private_key(), &bad_pk, DilithiumMode::Dilithium2);
    assert_eq!(result.unwrap_err(), dilithium::DilithiumError::InvalidKey);
}

#[test]
fn test_key_validation_tr_mismatch() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).expect("keygen failed");
    let mut bad_sk = kp.private_key().to_vec();
    // Corrupt tr field (starts at offset 2*SEEDBYTES = 64)
    bad_sk[64] ^= 0xFF;
    let result = DilithiumKeyPair::from_keys(&bad_sk, kp.public_key(), DilithiumMode::Dilithium2);
    assert_eq!(result.unwrap_err(), dilithium::DilithiumError::InvalidKey);
}

// ================================================================
// Existing tests
// ================================================================

#[test]
fn test_deterministic_keygen() {
    let seed = [42u8; 32];
    let kp1 = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &seed);
    let kp2 = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &seed);
    assert_eq!(kp1.public_key(), kp2.public_key());
    assert_eq!(kp1.private_key(), kp2.private_key());
}

#[test]
fn test_key_sizes() {
    let modes = [
        (DilithiumMode::Dilithium2, 1312, 2560, 2420),
        (DilithiumMode::Dilithium3, 1952, 4032, 3309),
        (DilithiumMode::Dilithium5, 2592, 4896, 4627),
    ];

    for (mode, pk_size, sk_size, sig_size) in &modes {
        let kp = DilithiumKeyPair::generate(*mode).expect("keygen failed");
        assert_eq!(kp.public_key().len(), *pk_size, "pk size for {:?}", mode);
        assert_eq!(kp.private_key().len(), *sk_size, "sk size for {:?}", mode);

        let sig = kp.sign(b"test", b"").expect("sign failed");
        assert_eq!(sig.as_bytes().len(), *sig_size, "sig size for {:?}", mode);
    }
}

#[test]
fn test_context_string_too_long() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).expect("keygen failed");
    let long_ctx = vec![0u8; 256];
    let result = kp.sign(b"msg", &long_ctx);
    assert!(result.is_err());
}
