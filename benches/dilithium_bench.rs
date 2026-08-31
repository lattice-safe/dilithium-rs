use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dilithium::params::*;
use dilithium::sign;

fn bench_keygen(c: &mut Criterion) {
    let seed = [42u8; SEEDBYTES];
    let mut group = c.benchmark_group("keygen");

    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| sign::keypair(black_box(DilithiumMode::Dilithium2), black_box(&seed)));
    });
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| sign::keypair(black_box(DilithiumMode::Dilithium3), black_box(&seed)));
    });
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| sign::keypair(black_box(DilithiumMode::Dilithium5), black_box(&seed)));
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let seed = [42u8; SEEDBYTES];
    let rnd = [0u8; RNDBYTES];
    let ctx = b"";
    let mut group = c.benchmark_group("sign");

    for (name, mode) in [
        ("ML-DSA-44", DilithiumMode::Dilithium2),
        ("ML-DSA-65", DilithiumMode::Dilithium3),
        ("ML-DSA-87", DilithiumMode::Dilithium5),
    ] {
        let (_, sk) = sign::keypair(mode, &seed);
        let mut sig = vec![0u8; mode.signature_bytes()];
        // The message varies per iteration. With a fixed (sk, msg, rnd) the
        // signing loop is deterministic, so the measurement would report the
        // rejection count of that one case — which differs by an order of
        // magnitude between cases and says nothing about the mode. Varying
        // the message samples the rejection-count distribution instead.
        let mut msg = [0u8; 1024];
        let mut counter: u32 = 0;
        group.bench_function(name, |b| {
            b.iter(|| {
                counter = counter.wrapping_add(1);
                msg[..4].copy_from_slice(&counter.to_le_bytes());
                sign::sign_signature(
                    black_box(mode),
                    black_box(&mut sig),
                    black_box(&msg),
                    black_box(ctx),
                    black_box(&rnd),
                    black_box(&sk),
                );
            });
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let seed = [42u8; SEEDBYTES];
    let msg = [0u8; 1024];
    let rnd = [0u8; RNDBYTES];
    let ctx = b"";
    let mut group = c.benchmark_group("verify");

    for (name, mode) in [
        ("ML-DSA-44", DilithiumMode::Dilithium2),
        ("ML-DSA-65", DilithiumMode::Dilithium3),
        ("ML-DSA-87", DilithiumMode::Dilithium5),
    ] {
        let (pk, sk) = sign::keypair(mode, &seed);
        let mut sig = vec![0u8; mode.signature_bytes()];
        sign::sign_signature(mode, &mut sig, &msg, ctx, &rnd, &sk);

        group.bench_function(name, |b| {
            b.iter(|| {
                let _ = sign::verify(
                    black_box(mode),
                    black_box(&sig),
                    black_box(&msg),
                    black_box(ctx),
                    black_box(&pk),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
