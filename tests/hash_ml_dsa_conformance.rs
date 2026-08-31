//! FIPS 204 §5.4 HashML-DSA conformance: the message representative `M'`.
//!
//! Algorithm 4 (`HashML-DSA.Sign`) and Algorithm 5 (`HashML-DSA.Verify`)
//! build
//!
//! ```text
//! M' = IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M
//! ```
//!
//! where `OID` is the DER encoding of the **pre-hash function's** object
//! identifier — for SHA-512, `2.16.840.1.101.3.4.2.3` — and `PH_M` is
//! `SHA-512(M)`. The OID does not depend on the ML-DSA parameter set; it is
//! what tells a verifier which pre-hash was applied. Getting it wrong yields
//! signatures that no conforming implementation can verify, which is exactly
//! the kind of error that round-trip tests cannot catch, so the bytes are
//! pinned here against an independent construction.

use sha2::{Digest, Sha512};

use dilithium::params::*;
use dilithium::safe_api::DilithiumKeyPair;
use dilithium::sign;

/// DER: 06 09 60 86 48 01 65 03 04 02 03  (id-sha512, 2.16.840.1.101.3.4.2.3)
const SHA512_DER_OID: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];

/// Independent, literal transcription of Algorithm 4 line 21.
fn expected_prehash_prefix(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1u8);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&SHA512_DER_OID);
    out.extend_from_slice(&Sha512::digest(msg));
    out
}

/// Independent transcription of the pure ML-DSA prefix (Algorithms 2/3).
fn expected_pure_prefix(ctx: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0u8);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out
}

#[test]
fn test_prehash_prefix_matches_fips204() {
    for ctx in [b"".as_slice(), b"ctx", &[0xAB; 255]] {
        for msg in [b"".as_slice(), b"abc", &[0x5A; 1000]] {
            let got = sign::prehash_prefix(msg, ctx).expect("ctx within limit");
            assert_eq!(got, expected_prehash_prefix(msg, ctx));

            // Structure: domain separator, length, ctx, OID, then the digest.
            assert_eq!(got[0], 1);
            assert_eq!(got[1] as usize, ctx.len());
            assert_eq!(&got[2..2 + ctx.len()], ctx);
            assert_eq!(&got[2 + ctx.len()..2 + ctx.len() + 11], &SHA512_DER_OID);
            assert_eq!(got.len(), 2 + ctx.len() + 11 + 64);
        }
    }
}

#[test]
fn test_pure_prefix_matches_fips204() {
    for ctx in [b"".as_slice(), b"ctx", &[0xAB; 255]] {
        let got = sign::pure_prefix(ctx).expect("ctx within limit");
        assert_eq!(got, expected_pure_prefix(ctx));
        assert_eq!(got[0], 0);
    }
}

/// FIPS 204 caps `|ctx|` at 255 bytes; both prefixes must refuse longer.
#[test]
fn test_prefixes_reject_oversized_context() {
    let long = vec![0u8; 256];
    assert!(sign::pure_prefix(&long).is_none());
    assert!(sign::prehash_prefix(b"m", &long).is_none());
}

/// The pre-hash OID is a property of SHA-512, not of the parameter set, so
/// the same 11 bytes appear in `M'` for ML-DSA-44/65/87.
#[test]
fn test_prehash_oid_is_parameter_set_independent() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        assert_eq!(mode.prehash_oid(), &SHA512_DER_OID);
        // ... and differs from the certificate algorithm identifiers.
        assert_ne!(mode.algorithm_oid(), &SHA512_DER_OID);
        assert_ne!(mode.hash_algorithm_oid(), &SHA512_DER_OID);
    }
}

/// A HashML-DSA signature must verify exactly when the `M'` inputs match,
/// and the pure and pre-hash domains must not cross-verify (the 0x00 vs 0x01
/// domain separator).
#[test]
fn test_prehash_domain_separation() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[11u8; SEEDBYTES]);
        let msg = b"domain separation";

        let mut sig = vec![0u8; mode.signature_bytes()];
        assert_eq!(
            sign::sign_hash(
                mode,
                &mut sig,
                msg,
                b"c",
                &[0u8; RNDBYTES],
                kp.private_key()
            ),
            0
        );

        assert!(sign::verify_hash(mode, &sig, msg, b"c", kp.public_key()));
        // Wrong context, wrong message, and the pure-mode verifier all fail.
        assert!(!sign::verify_hash(mode, &sig, msg, b"d", kp.public_key()));
        assert!(!sign::verify_hash(
            mode,
            &sig,
            b"other",
            b"c",
            kp.public_key()
        ));
        assert!(!sign::verify(mode, &sig, msg, b"c", kp.public_key()));

        // And a pure signature does not verify as a pre-hash one.
        let mut pure_sig = vec![0u8; mode.signature_bytes()];
        assert_eq!(
            sign::sign_signature(
                mode,
                &mut pure_sig,
                msg,
                b"c",
                &[0u8; RNDBYTES],
                kp.private_key()
            ),
            0
        );
        assert!(sign::verify(mode, &pure_sig, msg, b"c", kp.public_key()));
        assert!(!sign::verify_hash(
            mode,
            &pure_sig,
            msg,
            b"c",
            kp.public_key()
        ));
    }
}

/// `sign_hash`/`verify_hash` must refuse an over-long context.
#[test]
fn test_prehash_rejects_oversized_context() {
    let mode = ML_DSA_44;
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[12u8; SEEDBYTES]);
    let long = vec![0u8; 256];
    let mut sig = vec![0u8; mode.signature_bytes()];
    assert_eq!(
        sign::sign_hash(
            mode,
            &mut sig,
            b"m",
            &long,
            &[0u8; RNDBYTES],
            kp.private_key()
        ),
        -1
    );
    assert!(!sign::verify_hash(mode, &sig, b"m", &long, kp.public_key()));
    assert!(!sign::verify(mode, &sig, b"m", &long, kp.public_key()));
}
