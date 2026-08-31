//! Dilithium signing and verification.
//!
//! Faithful port of `sign.c` from the CRYSTALS-Dilithium reference.
//! All functions are parameterized by `DilithiumMode`.

use alloc::{vec, vec::Vec};

use crate::packing;
use crate::params::*;
use crate::poly::Poly;
use crate::polyvec::*;
use crate::symmetric::{shake256, shake256_multi};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Generate a Dilithium key pair.
///
/// Returns `(pk, sk)` as byte vectors.
#[must_use]
pub fn keypair(mode: DilithiumMode, random_seed: &[u8; SEEDBYTES]) -> (Vec<u8>, Vec<u8>) {
    let k = mode.k();
    let l = mode.l();

    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut expanded = [0u8; 2 * SEEDBYTES + CRHBYTES];

    // Derive rho, rhoprime, key from seed
    seedbuf[..SEEDBYTES].copy_from_slice(random_seed);
    seedbuf[SEEDBYTES] = k as u8;
    seedbuf[SEEDBYTES + 1] = l as u8;
    shake256(&mut expanded, &seedbuf[..SEEDBYTES + 2]);
    seedbuf.zeroize(); // S1: zeroize keying material

    let rho: [u8; SEEDBYTES] = expanded[..SEEDBYTES].try_into().unwrap();
    let mut rhoprime: [u8; CRHBYTES] = expanded[SEEDBYTES..SEEDBYTES + CRHBYTES]
        .try_into()
        .unwrap();
    let mut key: [u8; SEEDBYTES] = expanded[SEEDBYTES + CRHBYTES..].try_into().unwrap();
    expanded.zeroize(); // S1: zeroize keying material

    // Expand matrix A
    let mut mat = vec![PolyVecL::default(); K_MAX];
    matrix_expand(mode, &mut mat, &rho);

    // Sample short vectors s1, s2
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    polyvecl_uniform_eta(mode, &mut s1, &rhoprime, 0);
    polyveck_uniform_eta(mode, &mut s2, &rhoprime, l as u16);
    rhoprime.zeroize(); // S1: zeroize after sampling

    // t = A * NTT(s1)
    let mut s1hat = s1.clone();
    polyvecl_ntt(mode, &mut s1hat);
    let mut t1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut t1, &mat, &s1hat);
    polyveck_reduce(mode, &mut t1);
    polyveck_invntt_tomont(mode, &mut t1);

    // t = t + s2 (in place, no secret temporary)
    polyveck_add_assign(mode, &mut t1, &s2);

    // Extract t1 and t0
    polyveck_caddq(mode, &mut t1);
    let mut t1_high = PolyVecK::default();
    let mut t0 = PolyVecK::default();
    polyveck_power2round(mode, &mut t1_high, &mut t0, &t1);

    // Pack public key
    let mut pk = vec![0u8; mode.public_key_bytes()];
    packing::pack_pk(mode, &mut pk, &rho, &t1_high);

    // Compute tr = H(pk)
    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, &pk);

    // Pack secret key
    let mut sk = vec![0u8; mode.secret_key_bytes()];
    packing::pack_sk(mode, &mut sk, &rho, &tr, &key, &t0, &s1, &s2);

    // S1: zeroize all secret material left in local variables.
    // (rho, tr, t1_high are public; mat is derived from public rho.)
    key.zeroize();
    s1.zeroize();
    s1hat.zeroize();
    s2.zeroize();
    t0.zeroize();
    t1.zeroize(); // full t = A*s1 + s2 contains the secret low part t0

    (pk, sk)
}

/// Internal signing function with rejection sampling loop.
///
/// Returns the signature length, or 0 if `sk`/`sig` have wrong lengths.
pub fn sign_signature_internal(
    mode: DilithiumMode,
    sig: &mut [u8],
    m: &[u8],
    pre: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> usize {
    // F5: defensive length checks — never panic on malformed input
    if sk.len() != mode.secret_key_bytes() || sig.len() < mode.signature_bytes() {
        return 0;
    }

    let k = mode.k();
    let l = mode.l();
    let beta = mode.beta();
    let gamma1 = mode.gamma1();
    let gamma2 = mode.gamma2();
    let omega = mode.omega();

    // Unpack secret key
    let mut rho = [0u8; SEEDBYTES];
    let mut tr = [0u8; TRBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut t0 = PolyVecK::default();
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    packing::unpack_sk(
        mode, &mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk,
    );

    // Compute mu = CRH(tr, pre, msg)
    let mut mu = [0u8; CRHBYTES];
    shake256_multi(&mut mu, &[&tr, pre, m]);

    // Compute rhoprime = CRH(key, rnd, mu)
    let mut rhoprime = [0u8; CRHBYTES];
    shake256_multi(&mut rhoprime, &[&key, rnd, &mu]);
    key.zeroize(); // S2: zeroize keying material after use

    // Expand matrix and transform vectors
    let mut mat = vec![PolyVecL::default(); K_MAX];
    matrix_expand(mode, &mut mat, &rho);
    polyvecl_ntt(mode, &mut s1);
    polyveck_ntt(mode, &mut s2);
    polyveck_ntt(mode, &mut t0);

    let mut nonce: u16 = 0;
    let mut h = PolyVecK::default();

    // Secret-bearing temporaries are hoisted out of the rejection loop so
    // they live in a single stack slot (overwritten each iteration) and can
    // be zeroized once on exit (S2/F3).
    let mut y = PolyVecL::default();
    let mut y_ntt = PolyVecL::default();
    let mut z = PolyVecL::default();
    let mut w = PolyVecK::default();
    let mut w0 = PolyVecK::default();
    let mut cp = Poly::zero();

    // Public per-iteration scratch, also hoisted: previously these three
    // buffers were heap-allocated afresh on every rejection.
    let mut w1_high = PolyVecK::default();
    let mut w1_packed = vec![0u8; k * mode.polyw1_packedbytes()];
    let mut ctilde_buf = vec![0u8; mode.ctildebytes()];

    let siglen = loop {
        // Sample intermediate vector y
        polyvecl_uniform_gamma1(mode, &mut y, &rhoprime, nonce);
        // Matches the C reference. Overflow is unreachable in practice
        // (~9,300 consecutive rejections, p ≈ (3/4)^9300); wrapping_add
        // ensures debug builds cannot panic either.
        nonce = nonce.wrapping_add(l as u16);

        // w = A * NTT(y)
        y_ntt.clone_from(&y);
        polyvecl_ntt(mode, &mut y_ntt);
        matrix_pointwise_montgomery(mode, &mut w, &mat, &y_ntt);
        polyveck_reduce(mode, &mut w);
        polyveck_invntt_tomont(mode, &mut w);

        // Decompose w
        polyveck_caddq(mode, &mut w);
        polyveck_decompose(mode, &mut w1_high, &mut w0, &w);
        polyveck_pack_w1(mode, &mut w1_packed, &w1_high);

        // Compute challenge
        shake256_multi(&mut ctilde_buf, &[&mu, &w1_packed]);

        Poly::challenge(mode, &mut cp, &ctilde_buf);
        cp.ntt();

        // z = y + c*s1
        polyvecl_pointwise_poly_montgomery(mode, &mut z, &cp, &s1);
        polyvecl_invntt_tomont(mode, &mut z);
        polyvecl_add_assign(mode, &mut z, &y);
        polyvecl_reduce(mode, &mut z);
        if polyvecl_chknorm(mode, &z, gamma1 - beta) {
            continue;
        }

        // w0 = w0 - c*s2
        polyveck_pointwise_poly_montgomery(mode, &mut h, &cp, &s2);
        polyveck_invntt_tomont(mode, &mut h);
        polyveck_sub_assign(mode, &mut w0, &h);
        polyveck_reduce(mode, &mut w0);
        if polyveck_chknorm(mode, &w0, gamma2 - beta) {
            continue;
        }

        // Compute hints
        polyveck_pointwise_poly_montgomery(mode, &mut h, &cp, &t0);
        polyveck_invntt_tomont(mode, &mut h);
        polyveck_reduce(mode, &mut h);
        if polyveck_chknorm(mode, &h, gamma2) {
            continue;
        }

        polyveck_add_assign(mode, &mut w0, &h);
        let n = polyveck_make_hint(mode, &mut h, &w0, &w1_high);
        if n > omega {
            continue;
        }

        // Pack signature. c̃ is written to the caller's buffer only after
        // all rejection checks pass (F6): no rejected-iteration state
        // escapes into `sig`.
        packing::pack_sig(mode, sig, &ctilde_buf, &z, &h);
        break mode.signature_bytes();
    };

    // S2/F3: zeroize secret material before returning.
    // (z, cp, h are public — they are part of / derivable from the
    // signature. mu, tr, rho, mat are public. key was zeroized above.)
    s1.zeroize();
    s2.zeroize();
    t0.zeroize();
    rhoprime.zeroize();
    y.zeroize();
    y_ntt.zeroize();
    w.zeroize();
    w0.zeroize();

    siglen
}

/// Build the pure ML-DSA domain-separation prefix of `M'` (FIPS 204 §6.2,
/// Algorithms 2 and 3):
///
/// ```text
/// M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
/// ```
///
/// Returns `None` if `ctx` exceeds the 255-byte limit mandated by FIPS 204.
#[must_use]
pub fn pure_prefix(ctx: &[u8]) -> Option<Vec<u8>> {
    if ctx.len() > 255 {
        return None;
    }
    let mut pre = vec![0u8; 2 + ctx.len()];
    pre[0] = 0;
    pre[1] = ctx.len() as u8;
    pre[2..].copy_from_slice(ctx);
    Some(pre)
}

/// Build the complete HashML-DSA message representative `M'`
/// (FIPS 204 §5.4, Algorithms 4 and 5, line 21):
///
/// ```text
/// M' = IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M
/// ```
///
/// `OID` is the DER encoding of the **pre-hash function's** object identifier
/// — [`SHA512_OID`] here — and is therefore identical for ML-DSA-44/65/87.
/// `PH_M` is `SHA-512(M)`.
///
/// Returns `None` if `ctx` exceeds the 255-byte limit mandated by FIPS 204.
#[must_use]
pub fn prehash_prefix(msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    if ctx.len() > 255 {
        return None;
    }

    use sha2::Digest;
    let ph_m = sha2::Sha512::digest(msg);

    let oid = SHA512_OID;
    let mut pre = vec![0u8; 2 + ctx.len() + oid.len() + ph_m.len()];
    pre[0] = 1; // pre-hash domain separator
    pre[1] = ctx.len() as u8;
    let mut off = 2;
    pre[off..off + ctx.len()].copy_from_slice(ctx);
    off += ctx.len();
    pre[off..off + oid.len()].copy_from_slice(oid);
    off += oid.len();
    pre[off..off + ph_m.len()].copy_from_slice(&ph_m);
    Some(pre)
}

/// Sign a message with context string.
///
/// Returns 0 on success, or -1 on error (context too long, bad sk/sig length).
pub fn sign_signature(
    mode: DilithiumMode,
    sig: &mut [u8],
    m: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> i32 {
    let Some(pre) = pure_prefix(ctx) else {
        return -1;
    };

    if sign_signature_internal(mode, sig, m, &pre, rnd, sk) == 0 {
        return -1;
    }
    0
}

/// Verify a signature (internal API with prefix).
#[must_use]
pub fn verify_internal(mode: DilithiumMode, sig: &[u8], m: &[u8], pre: &[u8], pk: &[u8]) -> bool {
    let k = mode.k();
    let beta = mode.beta();
    let gamma1 = mode.gamma1();
    let ctilde_len = mode.ctildebytes();

    if sig.len() != mode.signature_bytes() {
        return false;
    }
    // F5: defensive length check — never panic on malformed input
    if pk.len() != mode.public_key_bytes() {
        return false;
    }

    // Unpack public key
    let mut rho = [0u8; SEEDBYTES];
    let mut t1 = PolyVecK::default();
    packing::unpack_pk(mode, &mut rho, &mut t1, pk);

    // Unpack signature
    let mut c = vec![0u8; ctilde_len];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();
    if packing::unpack_sig(mode, &mut c, &mut z, &mut h, sig) {
        return false;
    }
    if polyvecl_chknorm(mode, &z, gamma1 - beta) {
        return false;
    }

    // Compute CRH(H(pk), pre, msg)
    let mut mu = [0u8; CRHBYTES];
    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, pk);
    shake256_multi(&mut mu, &[&tr, pre, m]);

    // Reconstruct w1': Az - c * 2^d * t1
    let mut cp = Poly::zero();
    Poly::challenge(mode, &mut cp, &c);

    let mut mat = vec![PolyVecL::default(); K_MAX];
    matrix_expand(mode, &mut mat, &rho);

    polyvecl_ntt(mode, &mut z);
    let mut w1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut w1, &mat, &z);

    cp.ntt();
    polyveck_shiftl(mode, &mut t1);
    polyveck_ntt(mode, &mut t1);
    polyveck_pointwise_poly_montgomery_assign(mode, &mut t1, &cp);

    polyveck_sub_assign(mode, &mut w1, &t1);
    polyveck_reduce(mode, &mut w1);
    polyveck_invntt_tomont(mode, &mut w1);

    // Reconstruct w1 using hint
    polyveck_caddq(mode, &mut w1);
    polyveck_use_hint_assign(mode, &mut w1, &h);
    let mut buf = vec![0u8; k * mode.polyw1_packedbytes()];
    polyveck_pack_w1(mode, &mut buf, &w1);

    // Re-derive challenge and compare (constant-time to prevent side channels)
    let mut c2 = vec![0u8; ctilde_len];
    shake256_multi(&mut c2, &[&mu, &buf]);

    // FIPS 204 §7: constant-time comparison
    c.ct_eq(&c2).into()
}

/// Verify a signature with context string (pure ML-DSA, FIPS 204 §6.1).
#[must_use]
pub fn verify(mode: DilithiumMode, sig: &[u8], m: &[u8], ctx: &[u8], pk: &[u8]) -> bool {
    let Some(pre) = pure_prefix(ctx) else {
        return false;
    };

    verify_internal(mode, sig, m, &pre, pk)
}

/// HashML-DSA Sign (FIPS 204 §5.4 / §6.2, Algorithm 4).
///
/// Signs `SHA-512(msg)` instead of `msg` directly, embedding the DER-encoded
/// SHA-512 OID in the message representative `M'`.
pub fn sign_hash(
    mode: DilithiumMode,
    sig: &mut [u8],
    msg: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> i32 {
    let Some(pre) = prehash_prefix(msg, ctx) else {
        return -1;
    };

    if sign_signature_internal(mode, sig, &[], &pre, rnd, sk) == 0 {
        return -1;
    }
    0
}

/// HashML-DSA Verify (FIPS 204 §5.4 / §6.2, Algorithm 5).
///
/// Verifies against `SHA-512(msg)` with the DER-encoded SHA-512 OID embedded
/// in the message representative `M'`.
#[must_use]
pub fn verify_hash(mode: DilithiumMode, sig: &[u8], msg: &[u8], ctx: &[u8], pk: &[u8]) -> bool {
    let Some(pre) = prehash_prefix(msg, ctx) else {
        return false;
    };

    verify_internal(mode, sig, &[], &pre, pk)
}
