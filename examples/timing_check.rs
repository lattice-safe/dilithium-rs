//! Statistical constant-time measurement (dudect-style) for the two checks
//! that this crate made branchless in 0.4.0.
//!
//! The C reference short-circuits both `poly_chknorm` (returns on the first
//! out-of-bound coefficient) and `make_hint` (`||`/`&&` over the secret
//! `w0`). Reviewing the replacements at source level says nothing about what
//! LLVM emitted, so this measures the compiled code the way dudect does:
//!
//!   1. interleave measurements of two input classes,
//!   2. drop the slowest 10% (scheduler noise is one-sided),
//!   3. run Welch's t-test on the rest.
//!
//! Under dudect's convention `|t| > 10` means a leak is detected, `4.5..10`
//! is inconclusive, and below `4.5` no leak was detected at this sample size.
//! "No leak detected" is not a proof of constant time — it is a bound on
//! what this many samples could see.
//!
//! Each target is measured twice: once against the shipped implementation and
//! once against a local copy of the reference's short-circuiting form, which
//! serves as a **positive control**. If the control does not light up, the
//! harness is not measuring anything and the negative results are worthless.
//!
//! ```text
//! cargo run --release --example timing_check
//! ```
//!
//! Run it on an idle machine; a busy one inflates the noise floor and can
//! produce either false alarms or false silence.

use std::hint::black_box;
use std::time::Instant;

use dilithium::params::{DilithiumMode, Q};
use dilithium::poly::Poly;
use dilithium::rounding;

const MEASUREMENTS: usize = 200_000;
/// Independent repetitions per experiment. A single t-statistic wanders with
/// frequency and thermal drift; repeating exposes that instead of hiding it.
const ROUNDS: usize = 3;
/// Calls per timed sample: one `chknorm` is ~200 ns, comfortably above the
/// clock's resolution, but batching lifts the signal further above jitter.
const BATCH: usize = 8;
const CROP_FRACTION: f64 = 0.10;

// ────────────────────────────── statistics ──────────────────────────────

fn welch_t(a: &mut Vec<f64>, b: &mut Vec<f64>) -> f64 {
    // Crop the slow tail of both classes (interrupts, migrations, frequency
    // changes): they add variance without carrying input-dependent signal.
    for v in [&mut *a, &mut *b] {
        v.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let keep = ((v.len() as f64) * (1.0 - CROP_FRACTION)) as usize;
        v.truncate(keep.max(2));
    }

    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let mean = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (n - 1.0);
        (n, mean, var)
    };

    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    let denom = (va / na + vb / nb).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    (ma - mb) / denom
}

fn verdict(t: f64) -> &'static str {
    let t = t.abs();
    if t > 10.0 {
        "LEAK DETECTED"
    } else if t > 4.5 {
        "inconclusive"
    } else {
        "no leak detected"
    }
}

/// Measure one function on two input classes.
///
/// The two classes go through the **same call site** — `f` is a single
/// closure invoked with a different input — because comparing two closures
/// would compare two compiled code paths and report their differences as a
/// leak. The classes are interleaved so frequency and cache drift affect
/// both equally, and which class is timed first alternates so that any
/// first-vs-second bias cancels instead of loading onto one class.
fn measure<T, R, F>(mut f: F, class_a: &T, class_b: &T) -> f64
where
    F: FnMut(&T) -> R,
{
    // Fault the sample buffers in before timing: first-touch page faults
    // during the measurement loop are a systematic per-class cost that has
    // nothing to do with the function under test.
    let mut ta = vec![0.0f64; MEASUREMENTS];
    let mut tb = vec![0.0f64; MEASUREMENTS];
    ta.clear();
    tb.clear();

    // Warm up caches, branch predictors and the CPU frequency.
    for _ in 0..20_000 {
        black_box(f(black_box(class_a)));
        black_box(f(black_box(class_b)));
    }

    let time_once = |f: &mut F, input: &T| {
        let s = Instant::now();
        for _ in 0..BATCH {
            black_box(f(black_box(input)));
        }
        s.elapsed().as_nanos() as f64
    };

    for i in 0..MEASUREMENTS {
        if i % 2 == 0 {
            ta.push(time_once(&mut f, class_a));
            tb.push(time_once(&mut f, class_b));
        } else {
            tb.push(time_once(&mut f, class_b));
            ta.push(time_once(&mut f, class_a));
        }
    }

    welch_t(&mut ta, &mut tb)
}

/// Run an experiment `ROUNDS` times and report the median and the worst |t|.
/// The verdict follows the worst round: a leak that shows up in one round out
/// of three is still a leak.
fn report_rounds<T, R, F>(name: &str, mut make: impl FnMut() -> F, a: &T, b: &T)
where
    F: FnMut(&T) -> R,
{
    let mut ts: Vec<f64> = (0..ROUNDS).map(|_| measure(make(), a, b)).collect();
    let worst = ts
        .iter()
        .copied()
        .max_by(|x, y| x.abs().partial_cmp(&y.abs()).unwrap())
        .unwrap();
    ts.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let median = ts[ts.len() / 2];
    println!(
        "  {name:<46} median t = {median:8.2}   worst |t| = {:8.2}   {}",
        worst.abs(),
        verdict(worst)
    );
}

// ───────────────── reference forms (positive controls) ─────────────────

/// The C reference's `poly_chknorm`, including its early return.
fn chknorm_reference(p: &Poly, bound: i32) -> bool {
    if bound > (Q - 1) / 8 {
        return true;
    }
    for i in 0..256 {
        let mut t = p.coeffs[i] >> 31;
        t = p.coeffs[i] - (t & (2 * p.coeffs[i]));
        if t >= bound {
            return true;
        }
    }
    false
}

/// The C reference's `make_hint`, with `||`/`&&` short-circuiting.
///
/// `inline(never)` so the emitted code can be inspected with a disassembler
/// (see the note this example prints about what the compiler does to it).
#[inline(never)]
fn make_hint_reference(gamma2: i32, a0: i32, a1: i32) -> bool {
    a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)
}

fn main() {
    println!(
        "dudect-style timing measurement — {MEASUREMENTS} samples/class, \
         batch {BATCH}, {}% tail cropped",
        (CROP_FRACTION * 100.0) as u32
    );
    println!("thresholds: |t| > 10 leak, 4.5..10 inconclusive, < 4.5 no leak detected\n");

    let bound = 1000i32;

    // ── chknorm: violation at the first coefficient vs. none at all ──
    // The reference form returns after one iteration in class B.
    let clean = Poly::zero();
    let mut early = Poly::zero();
    early.coeffs[0] = bound + 1;

    println!("chknorm — no violation vs. violation at coefficient 0:");
    report_rounds(
        "shipped (branchless, full scan)",
        || |p: &Poly| p.chknorm(bound),
        &clean,
        &early,
    );
    report_rounds(
        "reference (early return) [positive control]",
        || |p: &Poly| chknorm_reference(p, bound),
        &clean,
        &early,
    );

    // ── chknorm: where the violating coefficient sits ──
    // Both classes reject; only the position differs. This is the leak that
    // matters during signing, because rejected candidates are secret.
    let mut late = Poly::zero();
    late.coeffs[255] = bound + 1;

    println!("\nchknorm — violation at coefficient 0 vs. at coefficient 255:");
    report_rounds(
        "shipped (branchless, full scan)",
        || |p: &Poly| p.chknorm(bound),
        &early,
        &late,
    );
    report_rounds(
        "reference (early return) [positive control]",
        || |p: &Poly| chknorm_reference(p, bound),
        &early,
        &late,
    );

    // ── make_hint: sign of the secret w0 coefficient ──
    let mode = DilithiumMode::Dilithium2;
    let g = mode.gamma2();
    let (hi, lo) = (g + 1, -g - 1);

    println!("\nmake_hint — a0 > gamma2 vs. a0 < -gamma2 (sign of secret w0):");
    report_rounds(
        "shipped (masked)",
        || |&a0: &i32| rounding::make_hint(mode, a0, 0),
        &hi,
        &lo,
    );
    report_rounds(
        "reference (short-circuit) [positive control]",
        || |&a0: &i32| make_hint_reference(g, a0, 0),
        &hi,
        &lo,
    );

    println!(
        "\nNote: the make_hint control does not fire, and that is expected. \
         On aarch64, LLVM compiles the reference's `||`/`&&` short-circuit \
         into branchless code — `ccmp`/`cset`/`csel`, no conditional branch \
         (disassemble make_hint_reference, which is #[inline(never)], to \
         see it). So there is nothing to detect on this target, and the \
         masked version's value is that it does not depend on the optimizer \
         making that choice. `chknorm`'s early `return` is real control \
         flow that no compiler can flatten, which is why that control fires \
         at |t| > 15000."
    );

    // ── Poly::make_hint over a whole polynomial ──
    let mut a0_hi = Poly::zero();
    let mut a0_lo = Poly::zero();
    for i in 0..256 {
        a0_hi.coeffs[i] = hi;
        a0_lo.coeffs[i] = lo;
    }
    let a1 = Poly::zero();

    println!("\nPoly::make_hint over 256 coefficients — all a0 > gamma2 vs. all a0 < -gamma2:");
    report_rounds(
        "shipped (masked)",
        || {
            |a0: &Poly| {
                let mut h = Poly::zero();
                Poly::make_hint(mode, &mut h, a0, &a1)
            }
        },
        &a0_hi,
        &a0_lo,
    );
    report_rounds(
        "reference (short-circuit) [positive control]",
        || {
            |a0: &Poly| {
                let mut count = 0usize;
                for i in 0..256 {
                    if make_hint_reference(g, a0.coeffs[i], a1.coeffs[i]) {
                        count += 1;
                    }
                }
                count
            }
        },
        &a0_hi,
        &a0_lo,
    );

    // Uniform-sign inputs make the reference's branch perfectly predictable,
    // so the control above cannot fire and its "no leak detected" says
    // nothing. The realistic case is a *mixed* w0: the branch then
    // mispredicts at a rate that depends on the secret signs. Class A
    // alternates, class B does not.
    let mut a0_mixed = Poly::zero();
    for i in 0..256 {
        a0_mixed.coeffs[i] = if i % 2 == 0 { hi } else { lo };
    }

    println!("\nPoly::make_hint — alternating signs (branch mispredicts) vs. uniform signs:");
    report_rounds(
        "shipped (masked)",
        || {
            |a0: &Poly| {
                let mut h = Poly::zero();
                Poly::make_hint(mode, &mut h, a0, &a1)
            }
        },
        &a0_mixed,
        &a0_hi,
    );
    report_rounds(
        "reference (short-circuit) [positive control]",
        || {
            |a0: &Poly| {
                let mut count = 0usize;
                for i in 0..256 {
                    if make_hint_reference(g, a0.coeffs[i], a1.coeffs[i]) {
                        count += 1;
                    }
                }
                count
            }
        },
        &a0_mixed,
        &a0_hi,
    );
}
