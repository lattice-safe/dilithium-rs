# syntax=docker/dockerfile:1

# Minimalist Linux (Alpine + musl) image for building and testing dilithium-rs.
#
# Build the test image:
#   docker build -t dilithium-rs-test .
# Run the full test suite:
#   docker run --rm dilithium-rs-test
# Open a shell for interactive work:
#   docker run --rm -it dilithium-rs-test sh

FROM rust:1-alpine AS test

# musl toolchain + git (some cargo operations expect it). No OpenSSL/C deps
# are needed — this crate is pure Rust (sha3/sha2/zeroize/subtle).
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy the manifest first so dependency compilation caches across source edits.
COPY Cargo.toml ./
COPY Cargo.lock* ./

# Bring in the full source tree.
COPY . .

# Warm the build cache (default features).
RUN cargo build --all-targets

# Default command: run the complete test suite with all features enabled.
CMD ["cargo", "test", "--all-features"]
