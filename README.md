# CKB Crypto-Agile Account Reference v0.1

Rust reference implementation of the frozen AccountLockV1, AccountStateV1,
AccountWitnessV1, and Verifier ABI v1 specifications in `docs/`.

AccountLock performs protocol/state/threshold checks and delegates every
algorithm-specific proof to a verifier child over one inherited pipe using
CKB2023 spawn. The included verifiers implement WebAuthn ES256/P-256,
ML-DSA-65, and SLH-DSA SHA2-128s. Positive cryptographic tests execute the
RISC-V verifier binaries inside CKB-VM.

## Prerequisites

- Rust stable with `rustfmt` and `clippy`
- `riscv64imac-unknown-none-elf` Rust target
- `ckb-debugger` on `PATH`

Install the Rust target with:

```sh
rustup target add riscv64imac-unknown-none-elf
```

## Exact build and test commands

Run from this directory:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude account-lock --exclude verifier-fixture --exclude verifier-p256 --exclude verifier-mldsa-adapter --exclude verifier-slhdsa-adapter -- -D warnings
cargo build --release --target riscv64imac-unknown-none-elf \
  -p account-lock -p verifier-fixture -p verifier-p256 \
  -p verifier-mldsa-adapter -p verifier-slhdsa-adapter
cargo test -p ckb-account-protocol -p ckb-account-host -p ckb-account-tests -- --nocapture
cargo run -p ckb-account-host --example export_vectors -- vectors/conformance-v1.bin
ckb-debugger --mode full --tx-file vectors/fixture-spend.json \
  --script input.0.lock --max-cycles 500000000
```

`scripts/check.sh` runs the same validation sequence. Tests use optimized
RISC-V binaries when present, so build the contracts first when measuring
cycles.

## Repository map

- `crates/protocol`: allocation-free wire parsers and validation
- `crates/host`: byte-exact encoders and digest construction
- `contracts/account-lock`: state resolution, transitions, thresholds, spawn ABI
- `contracts/verifier-*`: fixture and three cryptographic verifier children
- `tests`: host-driven CKB-VM integration suite
- `vectors`: deterministic binary conformance vector and debugger transactions
- `deploy`: local artifact hashes and upstream testnet/mainnet references

The VM suite covers all three real signature paths, pipe/exit semantics,
threshold-two rotation, sequence advancement, delayed recovery, state deletion,
and byte-identical AccountLock args. See `tests/TEST_MATRIX.md` for the precise
coverage boundary.

This is unaudited reference code. Review `SECURITY.md` before deployment.
