#![no_main]
use libfuzzer_sys::fuzz_target;
use dilithium::params::*;
use dilithium::sign;

// Fuzz the verifier with attacker-controlled signature bytes against a real
// public key, across all three modes and both pure and pre-hash domains.
//
// This is the exposed attack surface: `verify` must never panic and must
// never accept, whatever bytes it is handed. Unlike `fuzz_unpack_sig` it
// reaches past decoding into `UseHint`, the NTT and the challenge
// recomputation, so adversarial hints and out-of-range `z` are exercised
// end to end.
fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + SEEDBYTES {
        return;
    }
    let mode = match data[0] % 3 {
        0 => DilithiumMode::Dilithium2,
        1 => DilithiumMode::Dilithium3,
        _ => DilithiumMode::Dilithium5,
    };
    let seed: [u8; SEEDBYTES] = data[1..1 + SEEDBYTES].try_into().unwrap();
    let rest = &data[1 + SEEDBYTES..];

    let (pk, sk) = sign::keypair(mode, &seed);

    // 1. Arbitrary bytes as a signature: must be rejected, never panic.
    assert!(!sign::verify(mode, rest, b"msg", b"ctx", &pk));
    assert!(!sign::verify_hash(mode, rest, b"msg", b"ctx", &pk));

    // 2. A genuine signature with `rest` used to flip bytes: still rejected.
    let rnd = [0u8; RNDBYTES];
    let mut sig = vec![0u8; mode.signature_bytes()];
    assert_eq!(
        sign::sign_signature(mode, &mut sig, b"msg", b"ctx", &rnd, &sk),
        0
    );
    assert!(sign::verify(mode, &sig, b"msg", b"ctx", &pk));

    if rest.len() >= 3 {
        let idx = ((rest[0] as usize) << 8 | rest[1] as usize) % sig.len();
        let before = sig[idx];
        sig[idx] ^= rest[2].max(1);
        if sig[idx] != before {
            assert!(!sign::verify(mode, &sig, b"msg", b"ctx", &pk));
        }
    }
});
