#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::params::*;
use dilithium::sign;

// Fuzz sign→verify round-trip across all three modes:
// any message must sign and verify.
fuzz_target!(|data: &[u8]| {
    // First byte selects the mode, next 32 bytes are the seed, rest is message
    if data.len() < 1 + SEEDBYTES {
        return;
    }
    let mode = match data[0] % 3 {
        0 => DilithiumMode::Dilithium2,
        1 => DilithiumMode::Dilithium3,
        _ => DilithiumMode::Dilithium5,
    };
    let seed: [u8; SEEDBYTES] = data[1..1 + SEEDBYTES].try_into().unwrap();
    let msg = &data[1 + SEEDBYTES..];

    let (pk, sk) = sign::keypair(mode, &seed);

    let rnd = [0u8; RNDBYTES];
    let mut sig = vec![0u8; mode.signature_bytes()];
    let ret = sign::sign_signature(mode, &mut sig, msg, b"", &rnd, &sk);
    assert_eq!(ret, 0, "signing failed");

    assert!(
        sign::verify(mode, &sig, msg, b"", &pk),
        "Round-trip verification failed"
    );
});
