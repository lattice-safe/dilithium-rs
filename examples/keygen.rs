//! Generate an ML-DSA key pair and display sizes.

use dilithium::{DilithiumKeyPair, ML_DSA_44, ML_DSA_65, ML_DSA_87};

fn main() {
    for (name, mode) in [
        ("ML-DSA-44", ML_DSA_44),
        ("ML-DSA-65", ML_DSA_65),
        ("ML-DSA-87", ML_DSA_87),
    ] {
        let kp = DilithiumKeyPair::generate(mode).expect("keygen failed");
        println!(
            "{name}: pk={} bytes, sk={} bytes",
            kp.public_key().len(),
            kp.private_key().len()
        );
    }
}
