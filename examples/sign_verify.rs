//! Sign a message and verify the signature.

use dilithium::{DilithiumKeyPair, ML_DSA_65};

fn main() {
    let kp = DilithiumKeyPair::generate(ML_DSA_65).expect("keygen failed");

    let message = b"Hello, post-quantum world!";
    let context = b"example";

    // Sign
    let sig = kp.sign(message, context).expect("signing failed");
    println!(
        "Signed {} bytes → {} byte signature",
        message.len(),
        sig.len()
    );

    // Verify
    let ok = DilithiumKeyPair::verify(kp.public_key(), &sig, message, context, ML_DSA_65);
    println!("Verification: {}", if ok { "✅ PASS" } else { "❌ FAIL" });

    // Tampered message should fail
    let tampered =
        DilithiumKeyPair::verify(kp.public_key(), &sig, b"tampered!", context, ML_DSA_65);
    println!(
        "Tampered:     {}",
        if tampered {
            "❌ FAIL (unexpected)"
        } else {
            "✅ REJECTED"
        }
    );
}
