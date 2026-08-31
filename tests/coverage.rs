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
fn test_oid_der_encoding_is_well_formed() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        for (name, oid) in [
            ("algorithm_oid", mode.algorithm_oid()),
            ("hash_algorithm_oid", mode.hash_algorithm_oid()),
            ("prehash_oid", mode.prehash_oid()),
        ] {
            // DER: tag 0x06 (OBJECT IDENTIFIER), then a definite short-form
            // length that must equal the number of remaining content bytes.
            assert_eq!(oid[0], 0x06, "{name}: OID must start with tag 0x06");
            assert_eq!(
                oid[1] as usize,
                oid.len() - 2,
                "{name}: DER length byte must match the content length"
            );
            // 2.16.840.1.101.3.4.* — the NIST CSOR arc.
            assert_eq!(
                &oid[2..9],
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04],
                "{name}: must live under 2.16.840.1.101.3.4"
            );
        }
    }
}

/// FIPS 204 Algorithm 4/5 line 21: the OID embedded in `M'` identifies the
/// *pre-hash function*, so it is the SHA-512 OID 2.16.840.1.101.3.4.2.3 and
/// is identical for all three parameter sets.
#[test]
fn test_prehash_oid_is_sha512_and_mode_independent() {
    const SHA512_DER: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    ];
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        assert_eq!(mode.prehash_oid(), &SHA512_DER);
    }
    assert_eq!(dilithium::params::SHA512_OID, &SHA512_DER);
}

/// The algorithm-identifier OIDs are distinct per mode and distinct between
/// the pure and pre-hash variants (NIST CSOR sigAlgs 17-19 and 32-34).
#[test]
fn test_algorithm_oids_are_distinct() {
    use dilithium::params::*;
    let all = [
        ML_DSA_44_OID,
        ML_DSA_65_OID,
        ML_DSA_87_OID,
        HASH_ML_DSA_44_OID,
        HASH_ML_DSA_65_OID,
        HASH_ML_DSA_87_OID,
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "OIDs {i} and {j} must differ");
        }
        // sigAlgs arc: 2.16.840.1.101.3.4.3.<n>
        assert_eq!(all[i][9], 0x03);
    }
    assert_eq!(ML_DSA_44_OID[10], 17);
    assert_eq!(ML_DSA_65_OID[10], 18);
    assert_eq!(ML_DSA_87_OID[10], 19);
    assert_eq!(HASH_ML_DSA_44_OID[10], 32);
    assert_eq!(HASH_ML_DSA_65_OID[10], 33);
    assert_eq!(HASH_ML_DSA_87_OID[10], 34);
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

// ================================================================
// In-place vs out-of-place kernel equivalence
// ================================================================

/// Verification uses the in-place `*_assign` kernels to avoid cloning whole
/// polynomial vectors. They must agree exactly with the out-of-place forms
/// that mirror the C reference API.
#[test]
fn test_inplace_kernels_match_out_of_place() {
    use dilithium::poly::Poly;
    use dilithium::polyvec::*;

    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        // Deterministic pseudorandom inputs in the reduced range.
        let mut x: u32 = 0xC0FF_EE01;
        let mut next = move || {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 8) as i32 % Q
        };

        let mut a = Poly::zero();
        let mut v = PolyVecK::default();
        let mut h = PolyVecK::default();
        for i in 0..N {
            a.coeffs[i] = next();
        }
        for j in 0..mode.k() {
            for i in 0..N {
                v.vec[j].coeffs[i] = next().abs() % Q;
                h.vec[j].coeffs[i] = i32::from(next() & 1 == 0);
            }
        }

        // use_hint
        let mut out_of_place = PolyVecK::default();
        polyveck_use_hint(mode, &mut out_of_place, &v, &h);
        let mut in_place = v.clone();
        polyveck_use_hint_assign(mode, &mut in_place, &h);
        for j in 0..mode.k() {
            assert_eq!(
                out_of_place.vec[j].coeffs, in_place.vec[j].coeffs,
                "use_hint mismatch for {mode:?} poly {j}"
            );
        }

        // Single-polynomial use_hint
        let mut p_out = Poly::zero();
        Poly::use_hint(mode, &mut p_out, &v.vec[0], &h.vec[0]);
        let mut p_in = v.vec[0].clone();
        Poly::use_hint_assign(mode, &mut p_in, &h.vec[0]);
        assert_eq!(p_out.coeffs, p_in.coeffs);

        // pointwise_montgomery
        let mut prod_out = PolyVecK::default();
        polyveck_pointwise_poly_montgomery(mode, &mut prod_out, &a, &v);
        let mut prod_in = v.clone();
        polyveck_pointwise_poly_montgomery_assign(mode, &mut prod_in, &a);
        for j in 0..mode.k() {
            assert_eq!(
                prod_out.vec[j].coeffs, prod_in.vec[j].coeffs,
                "pointwise mismatch for {mode:?} poly {j}"
            );
        }

        // Vector add/sub, in-place and out-of-place
        let mut sum = PolyVecK::default();
        polyveck_add(mode, &mut sum, &v, &prod_out);
        let mut sum_in = v.clone();
        polyveck_add_assign(mode, &mut sum_in, &prod_out);
        let mut diff = PolyVecK::default();
        polyveck_sub(mode, &mut diff, &v, &prod_out);
        let mut diff_in = v.clone();
        polyveck_sub_assign(mode, &mut diff_in, &prod_out);
        for j in 0..mode.k() {
            assert_eq!(sum.vec[j].coeffs, sum_in.vec[j].coeffs);
            assert_eq!(diff.vec[j].coeffs, diff_in.vec[j].coeffs);
        }

        let mut l = PolyVecL::default();
        for j in 0..mode.l() {
            for i in 0..N {
                l.vec[j].coeffs[i] = next();
            }
        }
        let mut l_sum = PolyVecL::default();
        polyvecl_add(mode, &mut l_sum, &l, &l);
        let mut l_sum_in = l.clone();
        polyvecl_add_assign(mode, &mut l_sum_in, &l);
        for j in 0..mode.l() {
            assert_eq!(l_sum.vec[j].coeffs, l_sum_in.vec[j].coeffs);
        }
    }
}
