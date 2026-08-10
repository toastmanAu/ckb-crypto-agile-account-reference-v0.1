# Reproducible builds

This document defines the inputs used to reproduce the reference RISC-V ELFs.
It does not claim bit-for-bit reproducibility across arbitrary operating
systems, filesystems, or future toolchain distributions.

## Pinned inputs

- Rust 1.97.1 stable in `rust-toolchain.toml`
- Rust target `riscv64imac-unknown-none-elf`
- Dependency graph in `Cargo.lock`
- `ckb-std` 1.1.0 and `ckb-testtool` 1.1.1
- Linker flags in `.cargo/config.toml`
- Linker layout in `ckb-contract.ld`
- Release settings in the workspace `Cargo.toml`

Release overflow checks are enabled. The build uses size optimization, LTO, one
codegen unit, and abort-on-panic behavior.

## Clean build

From a clean checkout:

```sh
rustup component add rustfmt clippy
rustup target add riscv64imac-unknown-none-elf

cargo build --locked --release --target riscv64imac-unknown-none-elf \
  -p account-lock \
  -p verifier-fixture \
  -p verifier-p256 \
  -p verifier-mldsa-adapter \
  -p verifier-slhdsa-adapter
```

Do not deploy debug artifacts. The expected files are:

```text
target/riscv64imac-unknown-none-elf/release/account-lock
target/riscv64imac-unknown-none-elf/release/verifier-p256
target/riscv64imac-unknown-none-elf/release/verifier-mldsa-adapter
target/riscv64imac-unknown-none-elf/release/verifier-slhdsa-adapter
```

## CKB data hashes

With `ckb-cli` installed:

```sh
ckb-cli util blake2b --binary-path \
  target/riscv64imac-unknown-none-elf/release/account-lock
ckb-cli util blake2b --binary-path \
  target/riscv64imac-unknown-none-elf/release/verifier-p256
ckb-cli util blake2b --binary-path \
  target/riscv64imac-unknown-none-elf/release/verifier-mldsa-adapter
ckb-cli util blake2b --binary-path \
  target/riscv64imac-unknown-none-elf/release/verifier-slhdsa-adapter
```

Compare the results with `deploy/reference-deployments.json`. A mismatch means
the artifact must not be represented by that manifest entry.

## Conformance vector

```sh
cargo run --locked -p ckb-account-host --example export_vectors -- \
  /tmp/conformance-v1.bin
cmp vectors/conformance-v1.bin /tmp/conformance-v1.bin
sha256sum /tmp/conformance-v1.bin
```

Expected SHA-256:

```text
9645f8ee17461940326c81b90f1831bfd412e3370c8248ab50abee5fef4039a6
```

## Validation

Run `./scripts/check.sh` with `ckb-debugger` 1.1.1 on `PATH`. CI independently
builds the same targets, reproduces the conformance vector, verifies the pinned
debugger archive checksum, replays the debugger transaction, and rejects any
test run that changes tracked files.

For a release, record at least the source commit, Rust version output, host
platform, ELF sizes, CKB data hashes, test result, and deployment outpoints.
