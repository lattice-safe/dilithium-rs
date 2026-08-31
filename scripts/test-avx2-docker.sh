#!/usr/bin/env bash
# Run the test suite with the AVX2 NTT kernels actually executing.
#
# The AVX2 code is the crate's only unsafe block and cannot run on an ARM
# host: Rosetta 2 does not emulate AVX2, so `is_x86_feature_detected!("avx2")`
# is false there and the scalar fallback runs instead. Docker's linux/amd64
# platform (QEMU) does emulate AVX2, so the kernels really execute — this
# script checks that first and refuses to give a false pass if they do not.
#
#   ./scripts/test-avx2-docker.sh
#
# On an x86_64 host with AVX2 you do not need this: `cargo test --features
# simd` already exercises the kernels (which is what CI does).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT":/src:ro -w /work \
  rust:1-bookworm bash -euo pipefail -c '
    mkdir -p /work/repo
    (cd /src && tar cf - --exclude=target --exclude=.git .) | (cd /work/repo && tar xf -)
    cd /work/repo

    echo "== host arch: $(uname -m)"
    cat > /tmp/feat.rs <<RS
fn main() {
    let avx2 = std::arch::is_x86_feature_detected!("avx2");
    println!("avx2={avx2}");
    if !avx2 {
        eprintln!("AVX2 is not available: the simd tests would silently take the scalar path");
        std::process::exit(1);
    }
}
RS
    rustc -O /tmp/feat.rs -o /tmp/feat && /tmp/feat

    echo "== cargo test --release --features simd"
    cargo test --release --features simd
    echo "== cargo test --release --all-features"
    cargo test --release --all-features
  '
