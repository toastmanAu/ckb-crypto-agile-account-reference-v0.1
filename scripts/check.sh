#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets \
  --exclude account-lock \
  --exclude verifier-fixture \
  --exclude verifier-p256 \
  --exclude verifier-mldsa-adapter \
  --exclude verifier-slhdsa-adapter \
  -- -D warnings
cargo clippy --release --target riscv64imac-unknown-none-elf \
  -p account-lock \
  -p verifier-fixture \
  -p verifier-p256 \
  -p verifier-mldsa-adapter \
  -p verifier-slhdsa-adapter \
  -- -D warnings
cargo build --release --target riscv64imac-unknown-none-elf \
  -p account-lock \
  -p verifier-fixture \
  -p verifier-p256 \
  -p verifier-mldsa-adapter \
  -p verifier-slhdsa-adapter
cargo test -p ckb-account-protocol -p ckb-account-host -p ckb-account-tests -- --nocapture
cargo run -p ckb-account-host --example export_vectors -- vectors/conformance-v1.bin
ckb-debugger --mode full --tx-file vectors/fixture-spend.json \
  --script input.0.lock --max-cycles 500000000
