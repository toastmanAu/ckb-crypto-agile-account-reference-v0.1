# Security notes

This repository is unaudited reference code and must not be treated as a
production security review of the frozen protocol.

## Upstream implementation differences

- ML-DSA-65 uses the RustCrypto `ml-dsa` 0.1.1 API and the protocol's profile-1
  direct authorization-digest message. It was engineered against the requested
  RustCrypto-v2 profile, but does not vendor the `toastmanAu/ckb-mldsa-lock`
  source or inherit any audit claim from that repository.
- SLH-DSA SHA2-128s uses RustCrypto `slh-dsa` 0.2.0-rc.5 and wraps it in
  VerifierRequestV1. It does not vendor the exact audited implementation from
  Nervos `quantum-resistant-lock-script`; consequently that upstream audit does
  not cover this adapter or dependency version.
- The P-256 verifier contains a bounded, allocation-light parser for the flat
  WebAuthn `clientDataJSON` shape. The signed target fields must be present once,
  and escapes in those target string values are rejected. This is deliberately
  stricter than a general JSON parser.

## Consensus-facing properties

- Release overflow checks remain enabled and every untrusted offset/length uses
  checked arithmetic.
- AccountLock contains no algorithm-specific cryptography. Proofs are sent in a
  length-delimited VerifierRequestV1 through one inherited pipe; argv is empty.
- A verifier contributes weight only after `wait` reports child exit status 0.
- Account state identity is its Type ID script hash. Spend resolves exactly one
  state cell dep; rotate/recovery consumes and recreates exactly one identical
  type script. Deletion is rejected.
- AccountLock args remain exactly `0x01 || account_id` through transitions.

Before a public deployment, independently audit the wire parsers, the CKB2023
FD ownership behavior, WebAuthn policy choices, cryptographic dependencies, and
cycle/size denial-of-service bounds. Pin and reproduce all deployed ELF hashes.
