//! NIST ACVP conformance vectors (FIPS 204 / ML-DSA).
//!
//! These are the official NIST vectors from the ACVP server's
//! `gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204` test data
//! (`internalProjection.json`), trimmed to a subset that this crate can
//! execute — see `tests/data/acvp_ml_dsa.json`.
//!
//! They test something the C-reference KATs cannot: **interoperability with
//! an independent implementation**. In particular the HashML-DSA vectors pin
//! the pre-hash message representative `M'`, including the DER-encoded
//! SHA-512 OID that FIPS 204 Algorithm 4 inserts into it — a value this
//! crate got wrong before 0.4.0 and that no round-trip test can catch,
//! because signer and verifier shared the mistake.
//!
//! Only SHA-512 pre-hash vectors are used; the other approved pre-hash
//! functions (SHA-256, SHA3-*, SHAKE-*) are not implemented by this crate.
//!
//! Byte strings in the data file are base64; `*Sha256` fields are the
//! SHA-256 digest of the raw bytes (used where storing the full value would
//! bloat the repository).

use sha2::{Digest, Sha256};

use dilithium::params::*;
use dilithium::sign;

const VECTORS: &str = include_str!("data/acvp_ml_dsa.json");

/// Minimal standard-alphabet base64 decoder (no padding-tolerance games: the
/// generator emits canonical base64), so the test needs no extra dependency.
fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 byte {c:#x}"),
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut chunk = bytes;
    while chunk.len() >= 4 {
        let (a, b, c, d) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        let n = (val(a) << 18) | (val(b) << 12);
        out.push((n >> 16) as u8);
        if c != b'=' {
            let n = n | (val(c) << 6);
            out.push(((n >> 8) & 0xFF) as u8);
            if d != b'=' {
                let n = n | val(d);
                out.push((n & 0xFF) as u8);
            }
        }
        chunk = &chunk[4..];
    }
    assert!(chunk.is_empty(), "base64 length must be a multiple of 4");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn mode_of(ps: &str) -> DilithiumMode {
    match ps {
        "ML-DSA-44" => DilithiumMode::Dilithium2,
        "ML-DSA-65" => DilithiumMode::Dilithium3,
        "ML-DSA-87" => DilithiumMode::Dilithium5,
        other => panic!("unknown parameter set {other}"),
    }
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("vector file must be valid JSON")
}

fn field<'a>(v: &'a serde_json::Value, name: &str) -> &'a str {
    v[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {name}"))
}

/// FIPS 204 deterministic signing uses `rnd = 0^32`, which is what ACVP's
/// `deterministic: true` groups expect.
const DETERMINISTIC_RND: [u8; RNDBYTES] = [0u8; RNDBYTES];

// ================================================================
// ML-DSA.KeyGen (Algorithm 1 / 6)
// ================================================================

#[test]
fn acvp_keygen() {
    let v = vectors();
    let cases = v["keyGen"].as_array().expect("keyGen array");
    assert!(!cases.is_empty());

    for case in cases {
        let mode = mode_of(field(case, "ps"));
        let seed = b64(field(case, "seed"));
        let seed: [u8; SEEDBYTES] = seed.as_slice().try_into().expect("32-byte seed");

        let (pk, sk) = sign::keypair(mode, &seed);

        let tc = &case["tcId"];
        assert_eq!(
            sha256_hex(&pk),
            field(case, "pkSha256"),
            "keyGen tcId {tc}: public key mismatch"
        );
        assert_eq!(
            sha256_hex(&sk),
            field(case, "skSha256"),
            "keyGen tcId {tc}: secret key mismatch"
        );
    }
}

// ================================================================
// ML-DSA.Sign, pure (Algorithm 2), deterministic
// ================================================================

#[test]
fn acvp_siggen_pure_deterministic() {
    let v = vectors();
    let cases = v["sigGenPure"].as_array().expect("sigGenPure array");
    assert!(!cases.is_empty());

    for case in cases {
        let mode = mode_of(field(case, "ps"));
        let sk = b64(field(case, "sk"));
        let msg = b64(field(case, "message"));
        let ctx = b64(field(case, "context"));
        let tc = &case["tcId"];

        assert_eq!(sk.len(), mode.secret_key_bytes());

        let mut sig = vec![0u8; mode.signature_bytes()];
        let ret = sign::sign_signature(mode, &mut sig, &msg, &ctx, &DETERMINISTIC_RND, &sk);
        assert_eq!(ret, 0, "sigGen tcId {tc}: signing failed");

        assert_eq!(
            sha256_hex(&sig),
            field(case, "sigSha256"),
            "sigGen tcId {tc} ({}, |ctx|={}): signature mismatch",
            field(case, "ps"),
            ctx.len()
        );
    }
}

// ================================================================
// HashML-DSA.Sign / Verify (Algorithms 4 and 5), SHA-512 pre-hash
// ================================================================

/// Deterministic pre-hash vectors must reproduce **byte-for-byte**. This is
/// the external check on `M' = 0x01 || |ctx| || ctx || OID || SHA-512(M)`,
/// OID included: with the pre-0.4.0 OID this assertion fails.
#[test]
fn acvp_siggen_prehash_sha512_deterministic() {
    let v = vectors();
    let cases = v["sigGenPreHash"].as_array().expect("sigGenPreHash array");

    let mut count = 0;
    for case in cases {
        if !case["deterministic"].as_bool().expect("deterministic flag") {
            continue;
        }
        let mode = mode_of(field(case, "ps"));
        let msg = b64(field(case, "message"));
        let ctx = b64(field(case, "context"));
        let sk = b64(field(case, "sk"));
        let tc = &case["tcId"];

        let mut sig = vec![0u8; mode.signature_bytes()];
        let ret = sign::sign_hash(mode, &mut sig, &msg, &ctx, &DETERMINISTIC_RND, &sk);
        assert_eq!(ret, 0, "HashML-DSA tcId {tc}: signing failed");
        assert_eq!(
            sha256_hex(&sig),
            field(case, "sigSha256"),
            "HashML-DSA tcId {tc} ({}): signature mismatch — the pre-hash \
             message representative M' does not match FIPS 204",
            field(case, "ps")
        );
        count += 1;
    }

    // Guard against silently testing nothing if the data file is regenerated.
    assert!(
        count >= 3,
        "expected one deterministic SHA-512 pre-hash vector per mode, got {count}"
    );
}

/// The hedged pre-hash vectors use an unknown `rnd`, so verify NIST's own
/// signatures instead. The ACVP sigVer set contains no *valid* SHA-512
/// pre-hash case, so this is the only positive test of `verify_hash` against
/// a foreign signature.
#[test]
fn acvp_verify_prehash_sha512_foreign_signatures() {
    let v = vectors();
    let cases = v["sigGenPreHash"].as_array().expect("sigGenPreHash array");

    let mut count = 0;
    for case in cases {
        if case["deterministic"].as_bool().expect("deterministic flag") {
            continue;
        }
        let mode = mode_of(field(case, "ps"));
        let msg = b64(field(case, "message"));
        let ctx = b64(field(case, "context"));
        let pk = b64(field(case, "pk"));
        let sig = b64(field(case, "signature"));
        let tc = &case["tcId"];

        assert!(
            sign::verify_hash(mode, &sig, &msg, &ctx, &pk),
            "HashML-DSA tcId {tc} ({}): failed to verify a valid NIST signature",
            field(case, "ps")
        );
        // A one-bit change anywhere must break it.
        let mut tampered = sig.clone();
        tampered[0] ^= 1;
        assert!(!sign::verify_hash(mode, &tampered, &msg, &ctx, &pk));
        count += 1;
    }

    assert!(count >= 3, "expected hedged pre-hash vectors, got {count}");
}

// ================================================================
// ML-DSA.Verify / HashML-DSA.Verify (Algorithms 3 and 5)
// ================================================================

/// Includes NIST's negative cases: modified message, modified `c̃`
/// (commitment), modified hint, modified `z`. Each must be rejected.
#[test]
fn acvp_sigver() {
    let v = vectors();
    let cases = v["sigVer"].as_array().expect("sigVer array");
    assert!(!cases.is_empty());

    let mut accepted = 0;
    let mut rejected = 0;

    for case in cases {
        let mode = mode_of(field(case, "ps"));
        let pk = b64(field(case, "pk"));
        let msg = b64(field(case, "message"));
        let ctx = b64(field(case, "context"));
        let sig = b64(field(case, "signature"));
        let expected = case["testPassed"].as_bool().expect("testPassed flag");
        let prehash = case["preHash"].as_bool().expect("preHash flag");
        let tc = &case["tcId"];
        let reason = field(case, "reason");

        let got = if prehash {
            sign::verify_hash(mode, &sig, &msg, &ctx, &pk)
        } else {
            sign::verify(mode, &sig, &msg, &ctx, &pk)
        };

        assert_eq!(
            got,
            expected,
            "sigVer tcId {tc} ({}, prehash={prehash}): expected {expected}, got {got} — {reason}",
            field(case, "ps")
        );

        if expected {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    assert!(
        accepted > 0 && rejected > 0,
        "vector set must cover both outcomes"
    );
}
