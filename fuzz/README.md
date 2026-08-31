# Fuzzing dilithium-rs

Four targets, all covering every parameter set:

| Target | What it drives |
|--------|----------------|
| `fuzz_verify` | `verify` / `verify_hash` with arbitrary signature bytes against a real public key, plus one-bit mutations of genuine signatures. Reaches past decoding into `UseHint`, the NTT and the challenge recomputation. |
| `fuzz_unpack_sig` | `packing::unpack_sig` with arbitrary and exact-length input — the hint-decoding and malleability rules. |
| `fuzz_from_bytes` | `DilithiumKeyPair::from_bytes` and `DilithiumSignature::from_slice` with arbitrary bytes. |
| `fuzz_sign_verify` | sign→verify round-trip from an arbitrary seed and message; asserts the round trip always succeeds. |

## Running

```sh
cargo +nightly fuzz run fuzz_verify -- -max_total_time=600
```

## macOS: pass `--sanitizer=none`

On macOS 26 / aarch64 the AddressSanitizer-instrumented binary **deadlocks in
ASan's own initializer** before libFuzzer starts:

```
__malloc_init → AsanInitFromRtl → StaticSpinMutex::LockSlow → sched_yield  (forever)
```

The process never executes a single input, and under an external `timeout` it
looks like a clean exit — so a campaign can appear to pass while having
fuzzed nothing. Check the run printed `Done N runs` before believing it.

Use:

```sh
cargo +nightly fuzz run --sanitizer=none fuzz_verify -- -max_total_time=600
```

libFuzzer still detects panics, hangs and OOM; what is lost is ASan's
memory-error detection, which matters little here — the crate's only `unsafe`
is the SIMD NTT, which these targets do not compile (they build without the
`simd` feature).

On Linux x86_64 (CI, and the repository's Docker image) ASan works normally,
so the default sanitizer is the right choice there:

```sh
docker run --rm --platform linux/amd64 -v "$PWD":/src rust:1-bookworm bash -c \
  'cargo install cargo-fuzz && cd /src/fuzz && cargo fuzz run fuzz_verify -- -max_total_time=600'
```

## Corpus

Corpora are committed under `corpus/`. After a campaign, minimize before
committing:

```sh
cargo +nightly fuzz cmin --sanitizer=none <target>
```
