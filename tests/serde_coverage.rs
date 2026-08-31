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

/// Deserialization must not be a back door around the constructors: serde
/// runs the same FIPS 204 §7.1 validation as `from_bytes`.
#[test]
fn test_keypair_deserialize_rejects_tampered_key() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[1u8; 32]);

    // Flip a byte of the private key inside the serialized form.
    let mut value: serde_json::Value = serde_json::to_value(&kp).unwrap();
    let privkey = value["privkey"].as_array_mut().unwrap();
    let last = privkey.len() - 1;
    let byte = privkey[last].as_u64().unwrap() as u8;
    privkey[last] = serde_json::Value::from(byte ^ 0xFF);

    let err = serde_json::from_value::<DilithiumKeyPair>(value).unwrap_err();
    assert!(
        err.to_string().contains("key validation failed"),
        "unexpected error: {err}"
    );
}

/// A private key of the wrong length must be rejected, not silently accepted
/// into a key pair whose `mode` disagrees with its contents.
#[test]
fn test_keypair_deserialize_rejects_wrong_length() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[1u8; 32]);
    let mut value: serde_json::Value = serde_json::to_value(&kp).unwrap();
    value["privkey"].as_array_mut().unwrap().pop();

    let err = serde_json::from_value::<DilithiumKeyPair>(value).unwrap_err();
    assert!(
        err.to_string().contains("invalid format"),
        "unexpected error: {err}"
    );
}

/// A malformed `privkey` field must surface as a deserialization error rather
/// than panicking (exercises the `Zeroizing<Vec<u8>>` deserializer's error
/// path).
#[test]
fn test_keypair_deserialize_rejects_malformed_privkey_field() {
    let json = r#"{"privkey":"not-a-byte-array","pubkey":[],"mode":"Dilithium2"}"#;
    assert!(serde_json::from_str::<DilithiumKeyPair>(json).is_err());

    let json = r#"{"privkey":[1,2,3],"pubkey":"nope","mode":"Dilithium2"}"#;
    assert!(serde_json::from_str::<DilithiumKeyPair>(json).is_err());

    let json = r#"{"privkey":[1,2,3],"pubkey":[],"mode":"Dilithium9"}"#;
    assert!(serde_json::from_str::<DilithiumKeyPair>(json).is_err());
}

/// `Debug` must not leak the private key.
#[test]
fn test_keypair_debug_is_redacted() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium5, &[5u8; 32]);
    let rendered = format!("{kp:?}");
    assert!(rendered.contains("[REDACTED]"));
    // No run of real key bytes may appear in the rendering.
    let leaked = format!("{:?}", &kp.private_key()[..16]);
    assert!(!rendered.contains(&leaked));
}
