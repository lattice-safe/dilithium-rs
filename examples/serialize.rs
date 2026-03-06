//! Key pair serialization round-trip.

use dilithium::{DilithiumKeyPair, ML_DSA_44};

fn main() {
    let kp = DilithiumKeyPair::generate(ML_DSA_44).expect("keygen failed");

    // Binary round-trip
    let bytes = kp.to_bytes();
    println!("Serialized key pair: {} bytes", bytes.len());

    let kp2 = DilithiumKeyPair::from_bytes(&bytes).expect("deserialization failed");
    assert_eq!(kp.public_key(), kp2.public_key());
    assert_eq!(kp.private_key(), kp2.private_key());
    println!("Binary round-trip:   ✅ PASS");

    // Public key export
    let pk_bytes = kp.public_key_bytes();
    let (mode, pk) = DilithiumKeyPair::from_public_key(&pk_bytes).expect("pk parse failed");
    assert_eq!(pk, kp.public_key());
    println!(
        "Public key export:   ✅ mode={:?}, {} bytes",
        mode,
        pk.len()
    );

    // Sign with original, verify with deserialized
    let sig = kp.sign(b"test", b"").expect("sign failed");
    let ok = DilithiumKeyPair::verify(kp2.public_key(), &sig, b"test", b"", ML_DSA_44);
    println!(
        "Cross-key verify:    {}",
        if ok { "✅ PASS" } else { "❌ FAIL" }
    );
}
