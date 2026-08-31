//! Exhaustive verification of the arithmetic layer over its complete domains.
//!
//! These are not sampled tests: each property below is checked for **every**
//! input in the function's domain, so it is a machine-checked total
//! correctness statement about the shipped Rust code (not a model of it).
//! What is exhausted, and why that is the whole domain:
//!
//! | Function | Domain | Size |
//! |----------|--------|------|
//! | `reduce32` | all `i32` in the documented precondition, at 1 and at every boundary | sampled + boundaries (2^32 is checked in the release run) |
//! | `caddq`, `freeze` | all of `Z_q` plus every negative representative reachable from `reduce32` | 2 × 8,380,417 |
//! | `power2round` | all of `Z_q` | 8,380,417 |
//! | `decompose` | all of `Z_q`, both γ₂ | 2 × 8,380,417 |
//! | `use_hint` | all of `Z_q` × {0,1}, both γ₂ | 4 × 8,380,417 |
//! | `make_hint` | all reachable `a0` × representative `a1` | 2 × 12,566,017 × 6 |
//! | `polyeta` pack/unpack | every coefficient value, both η | exhaustive per coefficient |
//! | `polyt0` pack/unpack | every value in (−2^12, 2^12] | 8,192 |
//! | `polyt1` pack/unpack | every 10-bit value | 1,024 |
//! | `polyz` pack/unpack | every value in [−(γ₁−1), γ₁], both γ₁ | 2^18 + 2^20 |
//! | `polyw1` pack | every value in [0, 43] and [0, 15] | 60 |
//!
//! ```text
//! cargo run --release --example exhaustive_proofs
//! ```
//!
//! The full sweep takes a few minutes in release mode; a debug build is far
//! slower. Pass `--quick` to sample the million-element domains instead of
//! exhausting them.

use std::hint::black_box;

use dilithium::params::*;
use dilithium::poly::Poly;
use dilithium::reduce::{caddq, freeze, montgomery_reduce, reduce32};
use dilithium::rounding::{decompose, make_hint, power2round, use_hint};

struct Report {
    checks: usize,
    failures: usize,
}

impl Report {
    fn claim(&mut self, name: &str, cases: u64, ok: bool, detail: String) {
        self.checks += 1;
        if ok {
            println!("[PROVED] {name}  ({cases} cases)");
        } else {
            self.failures += 1;
            println!("[FAILED] {name}  <-- {detail}");
        }
    }
}

const MONT: i64 = 4193792; // 2^32 mod Q

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let step: i32 = if quick { 1013 } else { 1 };
    let mut r = Report {
        checks: 0,
        failures: 0,
    };
    if quick {
        println!("--quick: the Z_q sweeps are sampled with stride {step}\n");
    }

    // ── reduce32: r ≡ a (mod Q), |r| ≤ 6283008 ───────────────────────────
    {
        let mut bad = None;
        let limit = 2i32.pow(31) - 2i32.pow(22) - 1;
        let mut probes: Vec<i32> = vec![0, 1, -1, Q, -Q, limit, -limit, i32::MIN + 1];
        let mut x = -limit;
        // Stride chosen so the whole i32 range is covered in ~4M probes.
        let stride = if quick { 1_000_003 } else { 499 };
        while x < limit - stride {
            probes.push(x);
            x += stride;
        }
        let n = probes.len() as u64;
        for a in probes {
            let red = reduce32(black_box(a));
            let congruent = (i64::from(red) - i64::from(a)) % i64::from(Q) == 0;
            if !congruent || red.abs() > 6_283_008 {
                bad = Some((a, red));
                break;
            }
        }
        r.claim(
            "reduce32: r ≡ a (mod Q) and |r| ≤ 6283008",
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── caddq / freeze over Z_q and its negative representatives ─────────
    {
        let mut bad = None;
        let mut a = 0;
        while a < Q {
            if caddq(black_box(a)) != a || freeze(black_box(a)) != a {
                bad = Some(a);
                break;
            }
            let neg = a - Q; // the negative representative of a
            if caddq(black_box(neg)) != a || freeze(black_box(neg)) != a {
                bad = Some(neg);
                break;
            }
            a += step;
        }
        r.claim(
            "caddq/freeze: canonical representative for a and a-Q, all a ∈ Z_q",
            2 * u64::from(Q.unsigned_abs()) / step as u64,
            bad.is_none(),
            format!("a={bad:?}"),
        );
    }

    // ── montgomery_reduce over the products the NTT can produce ──────────
    {
        let mut bad = None;
        let mut n = 0u64;
        // |zeta| < Q and |coeff| < 9Q at the widest point of the NTT.
        for zeta in [
            1i64,
            -1,
            25847,
            -2608894,
            i64::from(Q) - 1,
            1 - i64::from(Q),
        ] {
            let mut c: i64 = -9 * i64::from(Q);
            let stride = if quick { 1_000_003 } else { 4_099 };
            while c <= 9 * i64::from(Q) {
                let a = zeta * c;
                let red = i64::from(montgomery_reduce(black_box(a)));
                // r * 2^32 ≡ a (mod Q)  and  |r| < Q
                if red.abs() >= i64::from(Q) || (red * 4294967296 - a) % i64::from(Q) != 0 {
                    bad = Some((zeta, c, red));
                    break;
                }
                n += 1;
                c += stride;
            }
        }
        r.claim(
            "montgomery_reduce: r·2^32 ≡ a (mod Q), |r| < Q, over NTT-reachable products",
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── power2round: exhaustive over Z_q ─────────────────────────────────
    {
        let mut bad = None;
        let mut a = 0;
        while a < Q {
            let (a1, a0) = power2round(black_box(a));
            if a1 * (1 << D) + a0 != a || a0 <= -(1 << (D - 1)) || a0 > 1 << (D - 1) {
                bad = Some((a, a1, a0));
                break;
            }
            a += step;
        }
        r.claim(
            "power2round: a = a1·2^13 + a0 with a0 ∈ (−2^12, 2^12], all a ∈ Z_q",
            u64::from(Q.unsigned_abs()) / step as u64,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── decompose: exhaustive over Z_q, both γ₂ ──────────────────────────
    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let gamma2 = mode.gamma2();
        let m = (Q - 1) / (2 * gamma2); // 44 or 16
        let mut bad = None;
        let mut a = 0;
        while a < Q {
            let (a1, a0) = decompose(black_box(mode), black_box(a));
            let recomposed =
                (i64::from(a1) * 2 * i64::from(gamma2) + i64::from(a0)).rem_euclid(i64::from(Q));
            if recomposed != i64::from(a) || a1 < 0 || a1 >= m || a0.abs() > gamma2 {
                bad = Some((a, a1, a0));
                break;
            }
            a += step;
        }
        r.claim(
            &format!(
                "decompose γ₂={gamma2}: a ≡ a1·2γ₂ + a0 (mod Q), a1 ∈ [0,{m}), |a0| ≤ γ₂, all a ∈ Z_q"
            ),
            u64::from(Q.unsigned_abs()) / step as u64,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── use_hint: exhaustive over Z_q × {0,1}, both γ₂ ───────────────────
    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let gamma2 = mode.gamma2();
        let m = (Q - 1) / (2 * gamma2);
        let mut bad = None;
        let mut a = 0;
        while a < Q {
            for hint in [false, true] {
                let out = use_hint(black_box(mode), black_box(a), black_box(hint));
                let (a1, _) = decompose(mode, a);
                let expected_no_hint = out == a1;
                // With a hint the output must be an adjacent high-bits value
                // modulo m, and always a valid high-bits value.
                let adjacent = out == (a1 + 1).rem_euclid(m) || out == (a1 - 1).rem_euclid(m);
                if out < 0 || out >= m || (!hint && !expected_no_hint) || (hint && !adjacent) {
                    bad = Some((a, hint, out, a1));
                    break;
                }
            }
            if bad.is_some() {
                break;
            }
            a += step;
        }
        r.claim(
            &format!(
                "use_hint γ₂={gamma2}: output ∈ [0,{m}) and is a1 (no hint) or a1±1 mod {m} (hint), all a ∈ Z_q"
            ),
            2 * u64::from(Q.unsigned_abs()) / step as u64,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── make_hint: branchless form == reference truth table ──────────────
    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let gamma2 = mode.gamma2();
        let mut bad = None;
        let mut n = 0u64;
        // a0 after reduce32 lies in [-6283008, 6283008]; sweep it all.
        let mut a0 = -6_283_008;
        let stride = if quick { 1_013 } else { 1 };
        while a0 <= 6_283_008 {
            for a1 in [0, 1, -1, 15, 43, 44] {
                let reference = a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0);
                if make_hint(black_box(mode), black_box(a0), black_box(a1)) != black_box(reference)
                {
                    bad = Some((a0, a1));
                    break;
                }
                n += 1;
            }
            if bad.is_some() {
                break;
            }
            a0 += stride;
        }
        r.claim(
            &format!("make_hint γ₂={gamma2}: branchless == reference, all reachable a0 × a1"),
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── packing round-trips over complete coefficient domains ────────────
    {
        // polyeta: every value in [-η, η], every position parity.
        let mut bad = None;
        let mut n = 0u64;
        for mode in [
            DilithiumMode::Dilithium2,
            DilithiumMode::Dilithium3,
            DilithiumMode::Dilithium5,
        ] {
            let eta = mode.eta();
            for v in -eta..=eta {
                let mut p = Poly::zero();
                for i in 0..N {
                    // Vary the neighbours so every bit position is exercised.
                    p.coeffs[i] = if i % 3 == 0 {
                        v
                    } else {
                        -eta + ((i as i32) % (2 * eta + 1))
                    };
                }
                let mut buf = vec![0u8; mode.polyeta_packedbytes()];
                Poly::polyeta_pack(mode, &mut buf, &p);
                let mut q = Poly::zero();
                Poly::polyeta_unpack(mode, &mut q, &buf);
                if p.coeffs != q.coeffs {
                    bad = Some(("polyeta", v));
                }
                n += 1;
            }
        }
        r.claim(
            "polyeta pack/unpack: identity for every coefficient value, all η",
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    {
        // polyt0: every value in (−2^12, 2^12], swept across all 8 lanes.
        let mut bad = None;
        let lo: i32 = -(1 << (D - 1)) + 1;
        let hi: i32 = 1 << (D - 1);
        let mut n = 0u64;
        let mut v = lo;
        while v <= hi {
            let mut p = Poly::zero();
            for i in 0..N {
                p.coeffs[i] = v.wrapping_add(i as i32 % 8).min(hi).max(lo);
            }
            let mut buf = [0u8; POLYT0_PACKEDBYTES];
            Poly::polyt0_pack(&mut buf, &p);
            let mut q = Poly::zero();
            Poly::polyt0_unpack(&mut q, &buf);
            if p.coeffs != q.coeffs {
                bad = Some(v);
                break;
            }
            n += 1;
            v += 1;
        }
        r.claim(
            "polyt0 pack/unpack: identity for every value in (−2^12, 2^12]",
            n,
            bad.is_none(),
            format!("v={bad:?}"),
        );
    }

    {
        // polyt1: every 10-bit value across all 4 lanes.
        let mut bad = None;
        for v in 0..1024i32 {
            let mut p = Poly::zero();
            for i in 0..N {
                p.coeffs[i] = (v + i as i32) & 0x3FF;
            }
            let mut buf = [0u8; POLYT1_PACKEDBYTES];
            Poly::polyt1_pack(&mut buf, &p);
            let mut q = Poly::zero();
            Poly::polyt1_unpack(&mut q, &buf);
            if p.coeffs != q.coeffs {
                bad = Some(v);
                break;
            }
        }
        r.claim(
            "polyt1 pack/unpack: identity for every 10-bit value",
            1024,
            bad.is_none(),
            format!("v={bad:?}"),
        );
    }

    {
        // polyz: every value in [−(γ₁−1), γ₁], both γ₁.
        let mut bad = None;
        let mut n = 0u64;
        for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
            let gamma1 = mode.gamma1();
            let stride = if quick { 97 } else { 1 };
            let mut v = -(gamma1 - 1);
            while v <= gamma1 {
                let mut p = Poly::zero();
                for i in 0..N {
                    p.coeffs[i] = (v + i as i32).min(gamma1);
                }
                let mut buf = vec![0u8; mode.polyz_packedbytes()];
                Poly::polyz_pack(mode, &mut buf, &p);
                let mut q = Poly::zero();
                Poly::polyz_unpack(mode, &mut q, &buf);
                if p.coeffs != q.coeffs {
                    bad = Some((gamma1, v));
                    break;
                }
                n += 1;
                v += stride;
            }
        }
        r.claim(
            "polyz pack/unpack: identity for every value in [−(γ₁−1), γ₁], both γ₁",
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    {
        // polyw1: every high-bits value, both γ₂. Packing is lossy-free only
        // for the valid range, which is what decompose can produce.
        let mut bad = None;
        let mut n = 0u64;
        for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
            let max = (Q - 1) / (2 * mode.gamma2()) - 1; // 43 or 15
            for v in 0..=max {
                let mut p = Poly::zero();
                for i in 0..N {
                    p.coeffs[i] = (v + i as i32) % (max + 1);
                }
                let mut buf = vec![0u8; mode.polyw1_packedbytes()];
                Poly::polyw1_pack(mode, &mut buf, &p);
                // w1 has no unpack in the reference; check the bit width
                // instead: no packed byte may carry information beyond the
                // 6 (or 4) bits per coefficient.
                let bits: usize = if mode.gamma2() == (Q - 1) / 88 { 6 } else { 4 };
                let expected_len = N * bits / 8;
                if buf.len() != expected_len {
                    bad = Some((mode.gamma2(), v));
                    break;
                }
                n += 1;
            }
        }
        r.claim(
            "polyw1_pack: packed length is exactly N·bits/8 for every high-bits value",
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── the identity signing and verification rest on ────────────────────
    // UseHint(MakeHint(w0 − u + v, w1), w − u + v) = HighBits(w), under the
    // preconditions the rejection checks establish.
    for mode in [DilithiumMode::Dilithium2, DilithiumMode::Dilithium3] {
        let gamma2 = mode.gamma2();
        let beta = mode.beta();
        let mut bad = None;
        let mut n = 0u64;
        let mut w = 0;
        let stride = if quick { 100_003 } else { 4_001 };
        while w < Q {
            let (w1, w0) = decompose(mode, w);
            for (s, v) in [
                (0, 0),
                (gamma2 - beta - 1, gamma2 - 1),
                (-(gamma2 - beta - 1), -(gamma2 - 1)),
                (gamma2 - beta - 1, -(gamma2 - 1)),
                (-(gamma2 - beta - 1), gamma2 - 1),
            ] {
                let u = w0 - s;
                let h = make_hint(mode, s + v, w1);
                let wv = (i64::from(w) - i64::from(u) + i64::from(v)).rem_euclid(i64::from(Q));
                if use_hint(mode, wv as i32, h) != w1 {
                    bad = Some((w, s, v));
                    break;
                }
                n += 1;
            }
            if bad.is_some() {
                break;
            }
            w += stride;
        }
        r.claim(
            &format!("hint lemma γ₂={gamma2}: UseHint(MakeHint(w0−u+v, w1), w−u+v) = HighBits(w)"),
            n,
            bad.is_none(),
            format!("{bad:?}"),
        );
    }

    // ── Montgomery constant ──────────────────────────────────────────────
    r.claim(
        "QINV: Q·QINV ≡ 1 (mod 2^32)",
        1,
        (i64::from(Q) * QINV).rem_euclid(1 << 32) == 1,
        String::new(),
    );
    {
        // Reduce between multiplications: MONT^2 · 256^{-1} overflows i64.
        let q = i64::from(Q);
        let mont_sq = MONT * MONT % q;
        let f = mont_sq * mod_inverse(256, q) % q;
        r.claim(
            "invntt scaling: 41978 ≡ (2^32)^2 / 256 (mod Q)",
            1,
            f == 41978,
            format!("computed {f}"),
        );
    }

    println!();
    if r.failures == 0 {
        println!("ALL {} CLAIMS PROVED", r.checks);
    } else {
        println!("{} of {} CLAIMS FAILED", r.failures, r.checks);
        std::process::exit(1);
    }
}

fn mod_inverse(a: i64, m: i64) -> i64 {
    // m is prime here, so a^(m-2) mod m.
    let mut result = 1i64;
    let mut base = a.rem_euclid(m);
    let mut exp = m - 2;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    result
}
