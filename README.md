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

To intentionally regenerate the tracked debugger transactions, run the two
fixture tests with `CKB_UPDATE_DEBUG_VECTORS=1`. Normal test runs never rewrite
tracked vectors.

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

The VM suite includes a single chained migration story covering P-256 spend,
P-256+ML-DSA threshold-two authorization, migration to ML-DSA+SLH-DSA,
threshold-one PQ spends, threshold-two rotation, a byte-distinct compatible
verifier upgrade, delayed recovery, and byte-identical AccountLock args. It also
covers pipe/exit semantics, sequence advancement, and state deletion. See
`tests/TEST_MATRIX.md` for the complete matrix.

This is unaudited reference code. Review `SECURITY.md` before deployment.
