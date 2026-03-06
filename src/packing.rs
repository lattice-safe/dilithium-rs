//! Key and signature packing/unpacking for Dilithium.
//!
//! Faithful port of `packing.c` from the CRYSTALS-Dilithium reference.

use crate::params::*;
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecL};

/// Pack public key: pk = (rho, t1).
pub fn pack_pk(mode: DilithiumMode, pk: &mut [u8], rho: &[u8; SEEDBYTES], t1: &PolyVecK) {
    pk[..SEEDBYTES].copy_from_slice(rho);
    let mut offset = SEEDBYTES;
    for i in 0..mode.k() {
        Poly::polyt1_pack(&mut pk[offset..offset + POLYT1_PACKEDBYTES], &t1.vec[i]);
        offset += POLYT1_PACKEDBYTES;
    }
}

/// Unpack public key: pk = (rho, t1).
pub fn unpack_pk(mode: DilithiumMode, rho: &mut [u8; SEEDBYTES], t1: &mut PolyVecK, pk: &[u8]) {
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let mut offset = SEEDBYTES;
    for i in 0..mode.k() {
        Poly::polyt1_unpack(&mut t1.vec[i], &pk[offset..offset + POLYT1_PACKEDBYTES]);
        offset += POLYT1_PACKEDBYTES;
    }
}

/// Pack secret key: sk = (rho, key, tr, s1, s2, t0).
pub fn pack_sk(
    mode: DilithiumMode,
    sk: &mut [u8],
    rho: &[u8; SEEDBYTES],
    tr: &[u8],
    key: &[u8; SEEDBYTES],
    t0: &PolyVecK,
    s1: &PolyVecL,
    s2: &PolyVecK,
) {
    let eta_packed = mode.polyeta_packedbytes();
    let mut offset = 0;

    // rho
    sk[offset..offset + SEEDBYTES].copy_from_slice(rho);
    offset += SEEDBYTES;

    // key
    sk[offset..offset + SEEDBYTES].copy_from_slice(key);
    offset += SEEDBYTES;

    // tr
    sk[offset..offset + TRBYTES].copy_from_slice(&tr[..TRBYTES]);
    offset += TRBYTES;

    // s1
    for i in 0..mode.l() {
        Poly::polyeta_pack(mode, &mut sk[offset..offset + eta_packed], &s1.vec[i]);
        offset += eta_packed;
    }

    // s2
    for i in 0..mode.k() {
        Poly::polyeta_pack(mode, &mut sk[offset..offset + eta_packed], &s2.vec[i]);
        offset += eta_packed;
    }

    // t0
    for i in 0..mode.k() {
        Poly::polyt0_pack(&mut sk[offset..offset + POLYT0_PACKEDBYTES], &t0.vec[i]);
        offset += POLYT0_PACKEDBYTES;
    }
}

/// Unpack secret key: sk = (rho, key, tr, s1, s2, t0).
pub fn unpack_sk(
    mode: DilithiumMode,
    rho: &mut [u8; SEEDBYTES],
    tr: &mut [u8],
    key: &mut [u8; SEEDBYTES],
    t0: &mut PolyVecK,
    s1: &mut PolyVecL,
    s2: &mut PolyVecK,
    sk: &[u8],
) {
    let eta_packed = mode.polyeta_packedbytes();
    let mut offset = 0;

    // rho
    rho.copy_from_slice(&sk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;

    // key
    key.copy_from_slice(&sk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;

    // tr
    tr[..TRBYTES].copy_from_slice(&sk[offset..offset + TRBYTES]);
    offset += TRBYTES;

    // s1
    for i in 0..mode.l() {
        Poly::polyeta_unpack(mode, &mut s1.vec[i], &sk[offset..offset + eta_packed]);
        offset += eta_packed;
    }

    // s2
    for i in 0..mode.k() {
        Poly::polyeta_unpack(mode, &mut s2.vec[i], &sk[offset..offset + eta_packed]);
        offset += eta_packed;
    }

    // t0
    for i in 0..mode.k() {
        Poly::polyt0_unpack(&mut t0.vec[i], &sk[offset..offset + POLYT0_PACKEDBYTES]);
        offset += POLYT0_PACKEDBYTES;
    }
}

/// Pack signature: sig = (c̃, z, h).
pub fn pack_sig(mode: DilithiumMode, sig: &mut [u8], c: &[u8], z: &PolyVecL, h: &PolyVecK) {
    let ctilde = mode.ctildebytes();
    let polyz_packed = mode.polyz_packedbytes();
    let omega = mode.omega();
    let k = mode.k();

    // c̃
    sig[..ctilde].copy_from_slice(&c[..ctilde]);
    let mut offset = ctilde;

    // z
    for i in 0..mode.l() {
        Poly::polyz_pack(mode, &mut sig[offset..offset + polyz_packed], &z.vec[i]);
        offset += polyz_packed;
    }

    // h (hint encoding)
    let h_start = offset;
    for i in 0..(omega + k) {
        sig[h_start + i] = 0;
    }

    let mut idx = 0;
    for i in 0..k {
        for j in 0..N {
            if h.vec[i].coeffs[j] != 0 {
                sig[h_start + idx] = j as u8;
                idx += 1;
            }
        }
        sig[h_start + omega + i] = idx as u8;
    }
}

/// Unpack signature: sig = (c̃, z, h).
/// Returns `true` on malformed signature.
pub fn unpack_sig(
    mode: DilithiumMode,
    c: &mut [u8],
    z: &mut PolyVecL,
    h: &mut PolyVecK,
    sig: &[u8],
) -> bool {
    let ctilde = mode.ctildebytes();
    let polyz_packed = mode.polyz_packedbytes();
    let omega = mode.omega();
    let k = mode.k();

    // c̃
    c[..ctilde].copy_from_slice(&sig[..ctilde]);
    let mut offset = ctilde;

    // z
    for i in 0..mode.l() {
        Poly::polyz_unpack(mode, &mut z.vec[i], &sig[offset..offset + polyz_packed]);
        offset += polyz_packed;
    }

    // h (hint decoding)
    let h_start = offset;
    let mut idx: usize = 0;
    for i in 0..k {
        for j in 0..N {
            h.vec[i].coeffs[j] = 0;
        }

        let end = sig[h_start + omega + i] as usize;
        if end < idx || end > omega {
            return true;
        }

        for j in idx..end {
            // Coefficients are ordered for strong unforgeability
            if j > idx && sig[h_start + j] <= sig[h_start + j - 1] {
                return true;
            }
            h.vec[i].coeffs[sig[h_start + j] as usize] = 1;
        }

        idx = end;
    }

    // Extra indices must be zero
    for j in idx..omega {
        if sig[h_start + j] != 0 {
            return true;
        }
    }

    false
}
