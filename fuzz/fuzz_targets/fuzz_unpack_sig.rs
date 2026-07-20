#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::params::*;
use dilithium::packing;
use dilithium::polyvec::{PolyVecK, PolyVecL};

/// Fuzz unpack_sig with arbitrary bytes across all three modes —
/// must never panic (including wrong-length input).
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mode = match data[0] % 3 {
        0 => DilithiumMode::Dilithium2,
        1 => DilithiumMode::Dilithium3,
        _ => DilithiumMode::Dilithium5,
    };
    let body = &data[1..];

    let mut c = vec![0u8; mode.ctildebytes()];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();

    // Arbitrary length input: must return true (malformed) — never panic
    let _ = packing::unpack_sig(mode, &mut c, &mut z, &mut h, body);

    // Exact-length input: true (malformed) or false (valid) — never panic
    let sig_len = mode.signature_bytes();
    if body.len() >= sig_len {
        let _ = packing::unpack_sig(mode, &mut c, &mut z, &mut h, &body[..sig_len]);
    }
});
