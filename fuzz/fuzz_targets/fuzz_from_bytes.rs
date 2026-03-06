#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::{DilithiumKeyPair, DilithiumSignature};

/// Fuzz DilithiumKeyPair::from_bytes with arbitrary bytes — must never panic.
fuzz_target!(|data: &[u8]| {
    // from_bytes should return Err, never panic
    let _ = DilithiumKeyPair::from_bytes(data);

    // DilithiumSignature::from_slice is infallible but should not panic
    let sig = DilithiumSignature::from_slice(data);
    let _ = sig.len();
});
