//! Additional coverage tests: error paths, low-level API guards,
//! malformed signature encodings, and helper functions not exercised
//! by the KAT / round-trip suites.

use dilithium::packing;
use dilithium::params::*;
use dilithium::poly::Poly;
use dilithium::polyvec::*;
use dilithium::safe_api::*;
use dilithium::sign;
use dilithium::symmetric::{shake256, Shake256State};
use zeroize::Zeroize;

const ALL_MODES: [DilithiumMode; 3] = [
    DilithiumMode::Dilithium2,
    DilithiumMode::Dilithium3,
    DilithiumMode::Dilithium5,
];

// ================================================================
// DilithiumError: Display + std::error::Error
// ================================================================

#[test]
fn test_error_display_all_variants() {
    assert_eq!(
        DilithiumError::RandomError.to_string(),
        "random number generation failed"
    );
    assert_eq!(DilithiumError::FormatError.to_string(), "invalid format");
    assert_eq!(DilithiumError::BadSignature.to_string(), "invalid signature");
    assert_eq!(DilithiumError::BadArgument.to_string(), "invalid argument");
    assert_eq!(
        DilithiumError::InvalidKey.to_string(),
        "key validation failed"
    );
}

#[test]
fn test_error_trait_object() {
    let e: Box<dyn std::error::Error> = Box::new(DilithiumError::BadSignature);
    assert!(!e.to_string().is_empty());
}

// ================================================================
// Mode accessors
// ================================================================

#[test]
fn test_mode_tag_roundtrip_and_invalid() {
    for mode in ALL_MODES {
        assert_eq!(DilithiumMode::from_tag(mode.mode_tag()), Some(mode));
    }
    assert_eq!(DilithiumMode::from_tag(0x00), None);
    assert_eq!(DilithiumMode::from_tag(0x04), None);
    assert_eq!(DilithiumMode::from_tag(0xFF), None);
}

#[test]
fn test_fips_names() {
    assert_eq!(DilithiumMode::Dilithium2.fips_name(), "ML-DSA-44");
    assert_eq!(DilithiumMode::Dilithium3.fips_name(), "ML-DSA-65");
    assert_eq!(DilithiumMode::Dilithium5.fips_name(), "ML-DSA-87");
}

// ================================================================
// Key pair serialization: to_bytes / from_bytes
// ================================================================

#[test]
fn test_keypair_to_from_bytes_roundtrip_all_modes() {
    for mode in ALL_MODES {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[7u8; 32]);
        let bytes = kp.to_bytes();
        assert_eq!(
            bytes.len(),
            1 + mode.public_key_bytes() + mode.secret_key_bytes()
        );
        assert_eq!(bytes[0], mode.mode_tag());

        let kp2 = DilithiumKeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(kp2.public_key(), kp.public_key());
        assert_eq!(kp2.private_key(), kp.private_key());
        assert_eq!(kp2.mode(), mode);
    }
}

#[test]
fn test_keypair_from_bytes_errors() {
    // Empty input
    assert_eq!(
        DilithiumKeyPair::from_bytes(&[]).unwrap_err(),
        DilithiumError::FormatError
    );
    // Invalid mode tag
    assert_eq!(
        DilithiumKeyPair::from_bytes(&[0xFF, 1, 2, 3]).unwrap_err(),
        DilithiumError::FormatError
    );
    // Valid tag, wrong length
    assert_eq!(
        DilithiumKeyPair::from_bytes(&[0x02, 1, 2, 3]).unwrap_err(),
        DilithiumError::FormatError
    );
    // Truncated by one byte
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[1u8; 32]);
    let mut bytes = kp.to_bytes();
    bytes.pop();
    assert_eq!(
        DilithiumKeyPair::from_bytes(&bytes).unwrap_err(),
        DilithiumError::FormatError
    );
}

// ================================================================
// Public key export: public_key_bytes / from_public_key
// ================================================================

#[test]
fn test_public_key_bytes_roundtrip() {
    for mode in ALL_MODES {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[9u8; 32]);
        let tagged = kp.public_key_bytes();
        assert_eq!(tagged[0], mode.mode_tag());

        let (mode2, pk) = DilithiumKeyPair::from_public_key(&tagged).unwrap();
        assert_eq!(mode2, mode);
        assert_eq!(pk, kp.public_key());

        // The recovered public key verifies signatures
        let sig = kp.sign_deterministic(b"msg", b"", &[0u8; 32]).unwrap();
        assert!(DilithiumKeyPair::verify(&pk, &sig, b"msg", b"", mode2));
    }
}

#[test]
fn test_from_public_key_errors() {
    assert_eq!(
        DilithiumKeyPair::from_public_key(&[]).unwrap_err(),
        DilithiumError::FormatError
    );
    assert_eq!(
        DilithiumKeyPair::from_public_key(&[0xFF, 0, 0]).unwrap_err(),
        DilithiumError::FormatError
    );
    assert_eq!(
        DilithiumKeyPair::from_public_key(&[0x02, 0, 0]).unwrap_err(),
        DilithiumError::FormatError
    );
}

// ================================================================
// DilithiumSignature helpers
// ================================================================

#[test]
fn test_signature_helpers() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[3u8; 32]);
    let sig = kp.sign_deterministic(b"m", b"", &[0u8; 32]).unwrap();

    let copy = DilithiumSignature::from_slice(sig.as_bytes());
    assert_eq!(copy, sig);
    assert_eq!(copy.len(), DilithiumMode::Dilithium2.signature_bytes());
    assert!(!copy.is_empty());

    let empty = DilithiumSignature::from_bytes(Vec::new());
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

// ================================================================
// HashML-DSA (prehash) round-trips and failure paths
// ================================================================

#[test]
fn test_prehash_roundtrip_all_modes() {
    for mode in ALL_MODES {
        let kp = DilithiumKeyPair::generate(mode).unwrap();
        let sig = kp.sign_prehash(b"prehash message", b"ctx").unwrap();
        assert!(DilithiumKeyPair::verify_prehash(
            kp.public_key(),
            &sig,
            b"prehash message",
            b"ctx",
            mode
        ));
        // Tampered message must fail
        assert!(!DilithiumKeyPair::verify_prehash(
            kp.public_key(),
            &sig,
            b"prehash message!",
            b"ctx",
            mode
        ));
        // Wrong ctx must fail
        assert!(!DilithiumKeyPair::verify_prehash(
            kp.public_key(),
            &sig,
            b"prehash message",
            b"other",
            mode
        ));
        // Pure verify must not accept a prehash signature
        assert!(!DilithiumKeyPair::verify(
            kp.public_key(),
            &sig,
            b"prehash message",
            b"ctx",
            mode
        ));
    }
}

#[test]
fn test_verify_prehash_wrong_sig_size() {
    let kp = DilithiumKeyPair::generate(DilithiumMode::Dilithium2).unwrap();
    let bad = DilithiumSignature::from_bytes(vec![0u8; 17]);
    assert!(!DilithiumKeyPair::verify_prehash(
        kp.public_key(),
        &bad,
        b"m",
        b"",
        DilithiumMode::Dilithium2
    ));
}

#[test]
fn test_sign_deterministic_ctx_too_long() {
    let kp = DilithiumKeyPair::generate_deterministic(DilithiumMode::Dilithium2, &[0u8; 32]);
    let long_ctx = vec![0u8; 256];
    assert_eq!(
        kp.sign_deterministic(b"m", &long_ctx, &[0u8; 32]).unwrap_err(),
        DilithiumError::BadArgument
    );
}

// ================================================================
// Low-level sign/verify guards (ctx length, buffer lengths)
// ================================================================

#[test]
fn test_lowlevel_ctx_too_long_paths() {
    let mode = DilithiumMode::Dilithium2;
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[5u8; 32]);
    let rnd = [0u8; RNDBYTES];
    let long_ctx = vec![0u8; 256];
    let mut sig = vec![0u8; mode.signature_bytes()];

    assert_eq!(
        sign::sign_signature(mode, &mut sig, b"m", &long_ctx, &rnd, kp.private_key()),
        -1
    );
    assert_eq!(
        sign::sign_hash(mode, &mut sig, b"m", &long_ctx, &rnd, kp.private_key()),
        -1
    );

    let good_sig = kp.sign_deterministic(b"m", b"", &rnd).unwrap();
    assert!(!sign::verify(
        mode,
        good_sig.as_bytes(),
        b"m",
        &long_ctx,
        kp.public_key()
    ));
    assert!(!sign::verify_hash(
        mode,
        good_sig.as_bytes(),
        b"m",
        &long_ctx,
        kp.public_key()
    ));
}

#[test]
fn test_lowlevel_sign_short_sig_buffer() {
    let mode = DilithiumMode::Dilithium2;
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[5u8; 32]);
    let rnd = [0u8; RNDBYTES];
    // Signature buffer too small: must return -1, not panic
    let mut short_sig = vec![0u8; 10];
    assert_eq!(
        sign::sign_signature(mode, &mut short_sig, b"m", b"", &rnd, kp.private_key()),
        -1
    );
}

#[test]
fn test_lowlevel_sign_hash_roundtrip() {
    for mode in ALL_MODES {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[6u8; 32]);
        let rnd = [0u8; RNDBYTES];
        let mut sig = vec![0u8; mode.signature_bytes()];
        assert_eq!(
            sign::sign_hash(mode, &mut sig, b"msg", b"c", &rnd, kp.private_key()),
            0
        );
        assert!(sign::verify_hash(mode, &sig, b"msg", b"c", kp.public_key()));
        assert!(!sign::verify_hash(mode, &sig, b"msX", b"c", kp.public_key()));
    }
}

#[test]
fn test_lowlevel_verify_wrong_sig_length() {
    let mode = DilithiumMode::Dilithium2;
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[8u8; 32]);
    assert!(!sign::verify(mode, &[0u8; 100], b"m", b"", kp.public_key()));
}

#[test]
fn test_verify_all_zero_signature_rejected() {
    // An all-zero signature of the correct length decodes (zero hints are a
    // valid encoding) but z fails the norm check: coeffs = gamma1 >= bound.
    for mode in ALL_MODES {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[4u8; 32]);
        let zero_sig = vec![0u8; mode.signature_bytes()];
        assert!(!sign::verify(mode, &zero_sig, b"m", b"", kp.public_key()));
    }
}

// ================================================================
// Malformed hint encodings in unpack_sig (strong unforgeability)
// ================================================================

fn valid_sig_and_keys(mode: DilithiumMode) -> (Vec<u8>, Vec<u8>) {
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[2u8; 32]);
    let sig = kp.sign_deterministic(b"hint test", b"", &[0u8; 32]).unwrap();
    (sig.as_bytes().to_vec(), kp.public_key().to_vec())
}

fn hint_region_start(mode: DilithiumMode) -> usize {
    mode.ctildebytes() + mode.l() * mode.polyz_packedbytes()
}

fn unpack(mode: DilithiumMode, sig: &[u8]) -> bool {
    let mut c = vec![0u8; mode.ctildebytes()];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();
    packing::unpack_sig(mode, &mut c, &mut z, &mut h, sig)
}

#[test]
fn test_unpack_sig_wrong_length_is_malformed() {
    let mode = DilithiumMode::Dilithium2;
    assert!(unpack(mode, &[0u8; 10]));
    assert!(unpack(mode, &[]));
}

#[test]
fn test_unpack_sig_hint_count_exceeds_omega() {
    let mode = DilithiumMode::Dilithium2;
    let (mut sig, pk) = valid_sig_and_keys(mode);
    let h = hint_region_start(mode);
    let omega = mode.omega();
    // Zero the hint region, then claim omega+1 hints in the first poly
    for b in sig[h..].iter_mut() {
        *b = 0;
    }
    sig[h + omega] = (omega + 1) as u8;
    assert!(unpack(mode, &sig), "count > omega must be malformed");
    assert!(!sign::verify(mode, &sig, b"hint test", b"", &pk));
}

#[test]
fn test_unpack_sig_hint_count_decreasing() {
    let mode = DilithiumMode::Dilithium2;
    let (mut sig, pk) = valid_sig_and_keys(mode);
    let h = hint_region_start(mode);
    let omega = mode.omega();
    for b in sig[h..].iter_mut() {
        *b = 0;
    }
    // Ascending indices for poly 0 (count 2), then count[1] < count[0]
    sig[h] = 3;
    sig[h + 1] = 7;
    sig[h + omega] = 2; // idx after poly 0
    sig[h + omega + 1] = 1; // end < idx → malformed
    assert!(unpack(mode, &sig), "decreasing count must be malformed");
    assert!(!sign::verify(mode, &sig, b"hint test", b"", &pk));
}

#[test]
fn test_unpack_sig_hint_indices_not_increasing() {
    let mode = DilithiumMode::Dilithium2;
    let (mut sig, pk) = valid_sig_and_keys(mode);
    let h = hint_region_start(mode);
    let omega = mode.omega();
    for b in sig[h..].iter_mut() {
        *b = 0;
    }
    // Two equal indices → violates strictly-increasing rule
    sig[h] = 7;
    sig[h + 1] = 7;
    for i in 0..mode.k() {
        sig[h + omega + i] = 2;
    }
    assert!(unpack(mode, &sig), "duplicate indices must be malformed");
    assert!(!sign::verify(mode, &sig, b"hint test", b"", &pk));
}

#[test]
fn test_unpack_sig_nonzero_hint_padding() {
    let mode = DilithiumMode::Dilithium2;
    let (mut sig, pk) = valid_sig_and_keys(mode);
    let h = hint_region_start(mode);
    for b in sig[h..].iter_mut() {
        *b = 0;
    }
    // All counts zero but a stray nonzero index byte in the padding
    sig[h + 5] = 9;
    assert!(unpack(mode, &sig), "nonzero padding must be malformed");
    assert!(!sign::verify(mode, &sig, b"hint test", b"", &pk));
}

#[test]
fn test_unpack_sig_valid_roundtrip() {
    for mode in ALL_MODES {
        let (sig, _) = valid_sig_and_keys(mode);
        assert!(!unpack(mode, &sig), "valid signature must decode");
    }
}

// ================================================================
// Tampered signature / message / ctx rejection (verify_internal path)
// ================================================================

#[test]
fn test_verify_tampered_inputs() {
    let mode = DilithiumMode::Dilithium2;
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[11u8; 32]);
    let sig = kp.sign_deterministic(b"msg", b"ctx", &[0u8; 32]).unwrap();

    // Baseline verifies
    assert!(DilithiumKeyPair::verify(
        kp.public_key(),
        &sig,
        b"msg",
        b"ctx",
        mode
    ));
    // Tampered c̃ (first byte)
    let mut bad = sig.as_bytes().to_vec();
    bad[0] ^= 0x01;
    let bad_sig = DilithiumSignature::from_bytes(bad);
    assert!(!DilithiumKeyPair::verify(
        kp.public_key(),
        &bad_sig,
        b"msg",
        b"ctx",
        mode
    ));
    // Tampered z (middle byte)
    let mut bad = sig.as_bytes().to_vec();
    let mid = mode.ctildebytes() + 100;
    bad[mid] ^= 0x01;
    let bad_sig = DilithiumSignature::from_bytes(bad);
    assert!(!DilithiumKeyPair::verify(
        kp.public_key(),
        &bad_sig,
        b"msg",
        b"ctx",
        mode
    ));
    // Wrong ctx
    assert!(!DilithiumKeyPair::verify(
        kp.public_key(),
        &sig,
        b"msg",
        b"ctY",
        mode
    ));
    // Wrong pk (valid length, different key)
    let kp2 = DilithiumKeyPair::generate_deterministic(mode, &[12u8; 32]);
    assert!(!DilithiumKeyPair::verify(
        kp2.public_key(),
        &sig,
        b"msg",
        b"ctx",
        mode
    ));
}

// ================================================================
// Poly / PolyVec helpers (add/sub variants, chknorm bound, zeroize)
// ================================================================

#[test]
fn test_poly_add_sub_assign_consistency() {
    let mut a = Poly::zero();
    let mut b = Poly::zero();
    for i in 0..N {
        a.coeffs[i] = i as i32;
        b.coeffs[i] = 2 * i as i32 + 1;
    }

    // add vs add_assign
    let mut c = Poly::zero();
    Poly::add(&mut c, &a, &b);
    let mut d = a.clone();
    Poly::add_assign(&mut d, &b);
    assert_eq!(c.coeffs, d.coeffs);

    // sub vs sub_assign
    let mut e = Poly::zero();
    Poly::sub(&mut e, &a, &b);
    let mut f = a.clone();
    Poly::sub_assign(&mut f, &b);
    assert_eq!(e.coeffs, f.coeffs);
}

#[test]
fn test_polyvec_add_sub_assign_consistency() {
    let mode = DilithiumMode::Dilithium5; // max K, L
    let mut u_l = PolyVecL::default();
    let mut v_l = PolyVecL::default();
    let mut u_k = PolyVecK::default();
    let mut v_k = PolyVecK::default();
    for i in 0..L_MAX {
        for j in 0..N {
            u_l.vec[i].coeffs[j] = (i * N + j) as i32;
            v_l.vec[i].coeffs[j] = 3 * j as i32;
        }
    }
    for i in 0..K_MAX {
        for j in 0..N {
            u_k.vec[i].coeffs[j] = (i * N + j) as i32;
            v_k.vec[i].coeffs[j] = 5 * j as i32;
        }
    }

    let mut w1 = PolyVecL::default();
    polyvecl_add(mode, &mut w1, &u_l, &v_l);
    let mut w2 = u_l.clone();
    polyvecl_add_assign(mode, &mut w2, &v_l);
    for i in 0..mode.l() {
        assert_eq!(w1.vec[i].coeffs, w2.vec[i].coeffs);
    }

    let mut x1 = PolyVecK::default();
    polyveck_add(mode, &mut x1, &u_k, &v_k);
    let mut x2 = u_k.clone();
    polyveck_add_assign(mode, &mut x2, &v_k);
    for i in 0..mode.k() {
        assert_eq!(x1.vec[i].coeffs, x2.vec[i].coeffs);
    }

    let mut y1 = PolyVecK::default();
    polyveck_sub(mode, &mut y1, &u_k, &v_k);
    let mut y2 = u_k.clone();
    polyveck_sub_assign(mode, &mut y2, &v_k);
    for i in 0..mode.k() {
        assert_eq!(y1.vec[i].coeffs, y2.vec[i].coeffs);
    }
}

#[test]
fn test_chknorm_bound_too_large() {
    let a = Poly::zero();
    // bound > (Q-1)/8 must always fail the check (return true)
    assert!(a.chknorm((Q - 1) / 8 + 1));
}

#[test]
fn test_polyvec_chknorm() {
    let mode = DilithiumMode::Dilithium2;
    let mut v = PolyVecL::default();
    assert!(!polyvecl_chknorm(mode, &v, 10));
    v.vec[mode.l() - 1].coeffs[N - 1] = 100;
    assert!(polyvecl_chknorm(mode, &v, 50));

    let mut w = PolyVecK::default();
    assert!(!polyveck_chknorm(mode, &w, 10));
    w.vec[0].coeffs[0] = -100;
    assert!(polyveck_chknorm(mode, &w, 50));
}

#[test]
fn test_zeroize_impls() {
    let mut p = Poly::zero();
    p.coeffs[0] = 42;
    p.coeffs[N - 1] = -7;
    p.zeroize();
    assert!(p.coeffs.iter().all(|&c| c == 0));

    let mut vl = PolyVecL::default();
    vl.vec[L_MAX - 1].coeffs[0] = 1;
    vl.zeroize();
    assert!(vl.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)));

    let mut vk = PolyVecK::default();
    vk.vec[K_MAX - 1].coeffs[0] = 1;
    vk.zeroize();
    assert!(vk.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)));
}

// ================================================================
// Symmetric primitives
// ================================================================

#[test]
fn test_shake256_state_matches_oneshot() {
    let mut state = Shake256State::default();
    state.absorb(b"hello ");
    state.absorb(b"world");
    let mut reader = state.finalize();
    let mut out1 = [0u8; 64];
    reader.squeeze(&mut out1);

    let mut out2 = [0u8; 64];
    shake256(&mut out2, b"hello world");
    assert_eq!(out1, out2);
}
