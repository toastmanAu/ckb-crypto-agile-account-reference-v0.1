# Audit scope

## Objective

Assess whether the implementation conforms byte-for-byte to AccountLockV1,
AccountStateV1, AccountWitnessV1, authorization digest v1, and Verifier ABI v1,
and whether the three verifier profiles safely enforce their documented proof
semantics in CKB-VM.

The source commit, release archive digest, compiler output, and deployment
outpoints must be recorded in the final engagement statement. A branch name or
moving tag is not an adequate audit target.

## Normative requirements

- `docs/REFERENCE_IMPLEMENTATION_SPEC.md`
- `schemas/account.mol`
- Constants and frozen identifiers in `crates/protocol/src/constants.rs`

If explanatory documentation conflicts with those files, auditors should flag
the conflict rather than silently choosing a new encoding.

## Consensus-critical source

- `contracts/account-lock/src/main.rs`
- `contracts/verifier-p256/src/main.rs`
- `contracts/verifier-mldsa-adapter/src/main.rs`
- `contracts/verifier-slhdsa-adapter/src/main.rs`
- `crates/protocol/src/`
- `ckb-contract.ld`
- `.cargo/config.toml`
- workspace release profile and locked dependency graph

## Supporting source

- `crates/host/src/lib.rs`
- `tests/src/lib.rs`
- `tests/src/story.rs`
- protocol and host test corpora
- conformance-vector exporters
- deployment and release packaging scripts

The fixture verifier is test-only. Confirm it is excluded from any production
account state or deployment recommendation.

## High-priority questions

1. Can state resolution accept no state, duplicate state, a foreign Type ID, or
   an input state during spend?
2. Can rotation/recovery delete state, change its full Type ID script, skip a
   sequence, or authorize against successor policy?
3. Does canonical sighash match CKB group rules for the first witness, remaining
   group witnesses, and extra witnesses?
4. Does the authorization digest include the exact frozen domain and every
   required field exactly once in the specified encoding?
5. Can a duplicate proof slot, capability mismatch, weight overflow, verifier
   failure, or unknown ABI contribute threshold weight?
6. Are pipe FD inheritance, parent/child close behavior, partial writes, EOF,
   spawn source/index, and `wait` handling correct under CKB2023?
7. Can verifier dep ambiguity or a hash-type mismatch resolve unintended code?
8. Are all state, witness, aux, proof, JSON, DER, public-key, and request lengths
   bounded and parsed without panic or wrap?
9. Does each verifier implement only the declared algorithm/profile and bind the
   expected key ID, message, RP/origin policy, or parameter set?
10. Do compiler features, allocator behavior, panic settings, and linker layout
    introduce executable-memory, undefined-behavior, or consensus risks?

## Cryptographic review boundaries

The engagement should distinguish adapter review from primitive cryptanalysis.
At minimum, verify dependency versions, feature flags, message semantics,
signature/key encodings, parameter selection, error handling, and known security
advisories.

The existing upstream audit status of Nervos FIPS205 code does not transfer to
this repository's RustCrypto SLH-DSA adapter. Likewise, engineering reference to
`toastmanAu/ckb-mldsa-lock` is not an audit of this ML-DSA adapter.

## Required build evidence

- Rust version and target output
- `Cargo.lock` and source commit
- clean release build log
- ELF byte lengths and CKB data hashes
- deterministic archive and SHA-256 manifest
- full local validation log
- successful GitHub CI run
- `ckb-debugger` version and replay output
- deployed cell bytes and outpoints, if deployment is in scope

Use `scripts/package_release.sh` to assemble a candidate, then independently
recompute rather than trusting its manifests.

## Existing automated evidence

- Strict parser and mutation corpus
- Host encoder/digest/sighash tests
- Real Type ID creation and exact-outpoint lifecycle
- Real P-256, ML-DSA-65, and SLH-DSA verification inside CKB-VM
- Hybrid thresholds, verifier upgrade, delayed recovery, and state deletion
- Foreign Type ID and unknown algorithm/flags/ABI rejection
- Signed input/output/data/witness mutation rejection
- Spawn/pipe fixture and child nonzero-exit rejection
- Deterministic conformance vector and debugger replay

Automated tests are evidence, not proof of absence of vulnerabilities.

## Out of scope unless added to the engagement

- Browser, authenticator firmware, wallet UI, or credential storage
- RPC/node compromise and chain-indexing correctness
- Testnet/mainnet deployment transactions and key custody
- Economic or fee-market analysis
- Cryptanalysis of standardized primitives
- Formal verification of Rust, LLVM, RISC-V, CKB-VM, or system scripts

## Expected findings format

For each finding, record severity, affected protocol invariant, exact source and
artifact version, exploit prerequisites, minimal reproducer, consensus impact,
recommended fix, and whether the fix requires a new protocol version. Any byte
format or digest change must not be shipped silently as AccountLockV1.
