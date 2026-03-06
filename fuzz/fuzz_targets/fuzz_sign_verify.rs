#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::params::*;
use dilithium::sign;

/// Fuzz sign→verify round-trip: any message should sign and verify.
fuzz_target!(|data: &[u8]| {
    // Use first 32 bytes as seed, rest as message
    if data.len() < SEEDBYTES {
        return;
    }
    let seed: [u8; SEEDBYTES] = data[..SEEDBYTES].try_into().unwrap();
    let msg = &data[SEEDBYTES..];

    let mode = DilithiumMode::Dilithium2;
    let (pk, sk) = sign::keypair(mode, &seed);

    let rnd = [0u8; RNDBYTES];
    let mut sig = vec![0u8; mode.signature_bytes()];
    sign::sign_signature(mode, &mut sig, msg, b"", &rnd, &sk);

    assert!(
        sign::verify(mode, &sig, msg, b"", &pk),
        "Round-trip verification failed"
    );
});
