#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::params::*;
use dilithium::packing;
use dilithium::poly::Poly;
use dilithium::polyvec::{PolyVecK, PolyVecL};

/// Fuzz unpack_sig with arbitrary bytes — must never panic.
fuzz_target!(|data: &[u8]| {
    let mode = DilithiumMode::Dilithium2;
    let sig_len = mode.signature_bytes();

    if data.len() < sig_len {
        return;
    }

    let mut c = vec![0u8; mode.ctildebytes()];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();

    // Should return true (malformed) or false (valid) — never panic
    let _ = packing::unpack_sig(mode, &mut c, &mut z, &mut h, &data[..sig_len]);
});
