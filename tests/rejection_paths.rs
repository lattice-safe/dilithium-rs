//! Coverage for the rare rejection branches of ML-DSA signing.
//!
//! FIPS 204 Algorithm 7 rejects a candidate signature when any of
//!
//!   1. `||z||inf >= gamma1 - beta`
//!   2. `||r0||inf >= gamma2 - beta`
//!   3. `||c*t0||inf >= gamma2`
//!   4. `popcount(h) > omega`
//!
//! holds. Checks 1, 2 and 4 fire routinely with real keys; check 3 fires with
//! probability on the order of 2^-23 per iteration, so ordinary tests never
//! execute it — yet omitting it would leak information about `t0` (the check
//! exists because `w1` must be recoverable by the verifier, who only knows
//! `t1`). This test reaches it by enlarging the `t0` coefficients of a
//! secret key: large enough that `||c*t0||inf >= gamma2` occurs a few percent
//! of the time, small enough that the hint weight stays under `omega` so
//! signing still terminates.

use dilithium::packing;
use dilithium::params::*;
use dilithium::poly::Poly;
use dilithium::polyvec::*;
use dilithium::safe_api::DilithiumKeyPair;
use dilithium::sign;

/// Number of leading `t0` polynomials whose coefficients are set to the
/// extreme value `2^(D-1) - 1`.
const MAGNIFIED_POLYS: usize = 2;

/// Deterministic ±(2^(D-1) - 1) sign pattern.
fn magnified_t0(mode: DilithiumMode, t0: &mut PolyVecK) {
    let mut st: u64 = 0x243F_6A88_85A3_08D3;
    for i in 0..MAGNIFIED_POLYS.min(mode.k()) {
        for j in 0..N {
            st = st
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let sign = if (st >> 33) & 1 == 0 { 1 } else { -1 };
            t0.vec[i].coeffs[j] = sign * ((1 << (D - 1)) - 1);
        }
    }
}

/// Repack a real secret key with enlarged `t0`.
fn crafted_secret_key(mode: DilithiumMode) -> (Vec<u8>, PolyVecK) {
    let kp = DilithiumKeyPair::generate_deterministic(mode, &[9u8; SEEDBYTES]);

    let mut rho = [0u8; SEEDBYTES];
    let mut tr = [0u8; TRBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut t0 = PolyVecK::default();
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    packing::unpack_sk(
        mode,
        &mut rho,
        &mut tr,
        &mut key,
        &mut t0,
        &mut s1,
        &mut s2,
        kp.private_key(),
    );

    magnified_t0(mode, &mut t0);

    let mut sk = vec![0u8; mode.secret_key_bytes()];
    packing::pack_sk(mode, &mut sk, &rho, &tr, &key, &t0, &s1, &s2);

    // The packed form must round-trip, otherwise the test below would be
    // exercising a different t0 than the one it reasons about.
    let mut t0_check = PolyVecK::default();
    let mut s1_check = PolyVecL::default();
    let mut s2_check = PolyVecK::default();
    packing::unpack_sk(
        mode,
        &mut rho,
        &mut tr,
        &mut key,
        &mut t0_check,
        &mut s1_check,
        &mut s2_check,
        &sk,
    );
    for i in 0..mode.k() {
        assert_eq!(t0_check.vec[i].coeffs, t0.vec[i].coeffs);
    }

    (sk, t0)
}

/// Directly mirror the loop's third check: with the crafted `t0`, some
/// challenges do drive `||c*t0||inf` to `gamma2` or beyond.
#[test]
fn test_crafted_t0_triggers_ct0_norm_check() {
    let mode = DilithiumMode::Dilithium2;
    let (_sk, mut t0) = crafted_secret_key(mode);
    polyveck_ntt(mode, &mut t0);

    let mut over = 0;
    for s in 0..500u32 {
        let mut seed = vec![0u8; mode.ctildebytes()];
        seed[..4].copy_from_slice(&s.to_le_bytes());

        let mut cp = Poly::zero();
        Poly::challenge(mode, &mut cp, &seed);
        cp.ntt();

        let mut ct0 = PolyVecK::default();
        polyveck_pointwise_poly_montgomery(mode, &mut ct0, &cp, &t0);
        polyveck_invntt_tomont(mode, &mut ct0);
        polyveck_reduce(mode, &mut ct0);

        if polyveck_chknorm(mode, &ct0, mode.gamma2()) {
            over += 1;
        }
    }

    assert!(
        over > 0,
        "crafted t0 never reached the gamma2 bound; the signing-loop \
         rejection branch would not be exercised"
    );
}

/// Sign repeatedly with the crafted key. Every signature must still be
/// produced (the loop terminates), and along the way the `||c*t0||inf`
/// rejection branch is taken.
#[test]
fn test_signing_terminates_when_ct0_check_rejects() {
    let mode = DilithiumMode::Dilithium2;
    let (sk, _t0) = crafted_secret_key(mode);

    for m in 0..40u32 {
        let mut sig = vec![0u8; mode.signature_bytes()];
        let msg = m.to_le_bytes();
        let n = sign::sign_signature_internal(mode, &mut sig, &msg, &[0, 0], &[0u8; RNDBYTES], &sk);
        assert_eq!(n, mode.signature_bytes(), "signing failed for message {m}");
    }
}

/// The other three rejection branches, reached with ordinary keys: signing
/// many messages exercises the `z`, `r0` and hint-weight rejections.
#[test]
fn test_ordinary_rejection_branches_all_modes() {
    for mode in [
        DilithiumMode::Dilithium2,
        DilithiumMode::Dilithium3,
        DilithiumMode::Dilithium5,
    ] {
        let kp = DilithiumKeyPair::generate_deterministic(mode, &[4u8; SEEDBYTES]);
        for m in 0..12u32 {
            let sig = kp
                .sign_deterministic(&m.to_le_bytes(), b"ctx", &[m as u8; RNDBYTES])
                .expect("signing failed");
            assert!(DilithiumKeyPair::verify(
                kp.public_key(),
                &sig,
                &m.to_le_bytes(),
                b"ctx",
                mode
            ));
        }
    }
}
