//! Dilithium signing and verification.
//!
//! Faithful port of `sign.c` from the CRYSTALS-Dilithium reference.
//! All functions are parameterized by `DilithiumMode`.

use crate::packing;
use crate::params::*;
use crate::poly::Poly;
use crate::polyvec::*;
use crate::symmetric::{shake256, shake256_multi};
use subtle::ConstantTimeEq;

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

    let rho: [u8; SEEDBYTES] = expanded[..SEEDBYTES].try_into().unwrap();
    let rhoprime: [u8; CRHBYTES] = expanded[SEEDBYTES..SEEDBYTES + CRHBYTES]
        .try_into()
        .unwrap();
    let key: [u8; SEEDBYTES] = expanded[SEEDBYTES + CRHBYTES..].try_into().unwrap();

    // Expand matrix A
    let mut mat = vec![PolyVecL::default(); K_MAX];
    matrix_expand(mode, &mut mat, &rho);

    // Sample short vectors s1, s2
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    polyvecl_uniform_eta(mode, &mut s1, &rhoprime, 0);
    polyveck_uniform_eta(mode, &mut s2, &rhoprime, l as u16);

    // t = A * NTT(s1)
    let mut s1hat = s1.clone();
    polyvecl_ntt(mode, &mut s1hat);
    let mut t1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut t1, &mat, &s1hat);
    polyveck_reduce(mode, &mut t1);
    polyveck_invntt_tomont(mode, &mut t1);

    // t = t + s2
    let t1_copy = t1.clone();
    polyveck_add(mode, &mut t1, &t1_copy, &s2);

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

    (pk, sk)
}

/// Internal signing function with rejection sampling loop.
pub fn sign_signature_internal(
    mode: DilithiumMode,
    sig: &mut [u8],
    m: &[u8],
    pre: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> usize {
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

    // Expand matrix and transform vectors
    let mut mat = vec![PolyVecL::default(); K_MAX];
    matrix_expand(mode, &mut mat, &rho);
    polyvecl_ntt(mode, &mut s1);
    polyveck_ntt(mode, &mut s2);
    polyveck_ntt(mode, &mut t0);

    let mut nonce: u16 = 0;
    let mut h = PolyVecK::default();

    loop {
        // Sample intermediate vector y
        let mut y = PolyVecL::default();
        polyvecl_uniform_gamma1(mode, &mut y, &rhoprime, nonce);
        nonce += l as u16;

        // w = A * NTT(y)
        let mut z_ntt = y.clone();
        polyvecl_ntt(mode, &mut z_ntt);
        let mut w1 = PolyVecK::default();
        matrix_pointwise_montgomery(mode, &mut w1, &mat, &z_ntt);
        polyveck_reduce(mode, &mut w1);
        polyveck_invntt_tomont(mode, &mut w1);

        // Decompose w
        polyveck_caddq(mode, &mut w1);
        let mut w1_high = PolyVecK::default();
        let mut w0 = PolyVecK::default();
        polyveck_decompose(mode, &mut w1_high, &mut w0, &w1);
        let mut w1_packed = vec![0u8; k * mode.polyw1_packedbytes()];
        polyveck_pack_w1(mode, &mut w1_packed, &w1_high);

        // Compute challenge
        let ctilde = mode.ctildebytes();
        let mut ctilde_buf = vec![0u8; ctilde];
        shake256_multi(&mut ctilde_buf, &[&mu, &w1_packed]);
        // Store c̃ into the signature buffer
        sig[..ctilde].copy_from_slice(&ctilde_buf);

        let mut cp = Poly::zero();
        Poly::challenge(mode, &mut cp, &ctilde_buf);
        cp.ntt();

        // z = y + c*s1
        let mut z = PolyVecL::default();
        polyvecl_pointwise_poly_montgomery(mode, &mut z, &cp, &s1);
        polyvecl_invntt_tomont(mode, &mut z);
        let z_copy = z.clone();
        polyvecl_add(mode, &mut z, &z_copy, &y);
        polyvecl_reduce(mode, &mut z);
        if polyvecl_chknorm(mode, &z, gamma1 - beta) {
            continue;
        }

        // w0 = w0 - c*s2
        polyveck_pointwise_poly_montgomery(mode, &mut h, &cp, &s2);
        polyveck_invntt_tomont(mode, &mut h);
        let w0_copy = w0.clone();
        polyveck_sub(mode, &mut w0, &w0_copy, &h);
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

        let w0_copy2 = w0.clone();
        polyveck_add(mode, &mut w0, &w0_copy2, &h);
        let n = polyveck_make_hint(mode, &mut h, &w0, &w1_high);
        if n > omega {
            continue;
        }

        // Pack signature
        packing::pack_sig(mode, sig, &ctilde_buf, &z, &h);
        return mode.signature_bytes();
    }
}

/// Sign a message with context string.
///
/// Returns signature length on success, or 0 on error (context too long).
pub fn sign_signature(
    mode: DilithiumMode,
    sig: &mut [u8],
    m: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> i32 {
    if ctx.len() > 255 {
        return -1;
    }

    // Build prefix: (0, ctxlen, ctx)
    let mut pre = vec![0u8; 2 + ctx.len()];
    pre[0] = 0;
    pre[1] = ctx.len() as u8;
    pre[2..].copy_from_slice(ctx);

    sign_signature_internal(mode, sig, m, &pre, rnd, sk);
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
    let t1_clone = t1.clone();
    polyveck_pointwise_poly_montgomery(mode, &mut t1, &cp, &t1_clone);

    let w1_copy = w1.clone();
    polyveck_sub(mode, &mut w1, &w1_copy, &t1);
    polyveck_reduce(mode, &mut w1);
    polyveck_invntt_tomont(mode, &mut w1);

    // Reconstruct w1 using hint
    polyveck_caddq(mode, &mut w1);
    let w1_copy2 = w1.clone();
    polyveck_use_hint(mode, &mut w1, &w1_copy2, &h);
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
    if ctx.len() > 255 {
        return false;
    }

    let mut pre = vec![0u8; 2 + ctx.len()];
    pre[0] = 0;
    pre[1] = ctx.len() as u8;
    pre[2..].copy_from_slice(ctx);

    verify_internal(mode, sig, m, &pre, pk)
}

/// HashML-DSA Sign (FIPS 204 §6.2).
///
/// Signs `SHA-512(msg)` instead of `msg` directly, embedding the hash OID.
pub fn sign_hash(
    mode: DilithiumMode,
    sig: &mut [u8],
    msg: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &[u8],
) -> i32 {
    if ctx.len() > 255 {
        return -1;
    }

    // Hash the message with SHA-512
    use sha2::Digest;
    let ph_m = sha2::Sha512::digest(msg);

    // Build prefix: (1, ctxlen, ctx, OID, H(msg))
    let oid = mode.hash_oid();
    let mut pre = vec![0u8; 2 + ctx.len() + oid.len() + ph_m.len()];
    pre[0] = 1; // prehash indicator
    pre[1] = ctx.len() as u8;
    let mut off = 2;
    pre[off..off + ctx.len()].copy_from_slice(ctx);
    off += ctx.len();
    pre[off..off + oid.len()].copy_from_slice(oid);
    off += oid.len();
    pre[off..off + ph_m.len()].copy_from_slice(&ph_m);

    sign_signature_internal(mode, sig, &[], &pre, rnd, sk);
    0
}

/// HashML-DSA Verify (FIPS 204 §6.2).
///
/// Verifies against `SHA-512(msg)` with the hash OID embedded.
#[must_use]
pub fn verify_hash(mode: DilithiumMode, sig: &[u8], msg: &[u8], ctx: &[u8], pk: &[u8]) -> bool {
    if ctx.len() > 255 {
        return false;
    }

    use sha2::Digest;
    let ph_m = sha2::Sha512::digest(msg);

    let oid = mode.hash_oid();
    let mut pre = vec![0u8; 2 + ctx.len() + oid.len() + ph_m.len()];
    pre[0] = 1;
    pre[1] = ctx.len() as u8;
    let mut off = 2;
    pre[off..off + ctx.len()].copy_from_slice(ctx);
    off += ctx.len();
    pre[off..off + oid.len()].copy_from_slice(oid);
    off += oid.len();
    pre[off..off + ph_m.len()].copy_from_slice(&ph_m);

    verify_internal(mode, sig, &[], &pre, pk)
}
