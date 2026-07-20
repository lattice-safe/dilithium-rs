//! Serde serialization coverage (requires `--features serde`).
#![cfg(feature = "serde")]

use dilithium::safe_api::*;

#[test]
fn test_keypair_serde_roundtrip() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[1u8; 32]);
    let json = serde_json::to_string(&kp).unwrap();
    let kp2: DilithiumKeyPair = serde_json::from_str(&json).unwrap();
    assert_eq!(kp2.public_key(), kp.public_key());
    assert_eq!(kp2.private_key(), kp.private_key());
    assert_eq!(kp2.mode(), kp.mode());

    // The deserialized key pair still signs and verifies
    let sig = kp2.sign_deterministic(b"m", b"", &[0u8; 32]).unwrap();
    assert!(DilithiumKeyPair::verify(
        kp2.public_key(),
        &sig,
        b"m",
        b"",
        kp2.mode()
    ));
}

#[test]
fn test_signature_serde_roundtrip() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[1u8; 32]);
    let sig = kp.sign_deterministic(b"m", b"", &[0u8; 32]).unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    let sig2: DilithiumSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig2, sig);
}

#[test]
fn test_mode_and_error_serde_roundtrip() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let mode2: DilithiumMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode2, mode);
    }
    let err = DilithiumError::BadSignature;
    let json = serde_json::to_string(&err).unwrap();
    let err2: DilithiumError = serde_json::from_str(&json).unwrap();
    assert_eq!(err2, err);
}
