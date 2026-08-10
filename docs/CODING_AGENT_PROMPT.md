# Surgical Coding-Agent Prompt

You are implementing the reference repository in this package. Treat the RFC/specification files as immutable protocol requirements.

OBJECTIVE:
Deliver a compiling Rust workspace and CKB-VM test suite implementing AccountLockV1, AccountStateV1, AccountWitnessV1 and Verifier ABI v1 with three authentication paths:
1. WebAuthn ES256/P-256,
2. ML-DSA-65 RustCrypto profile,
3. SLH-DSA/FIPS205 SHA2-128s profile.

NON-NEGOTIABLE:
- Do not redesign byte formats.
- Do not change algorithm IDs, magic bytes, digest domains, threshold semantics or version numbers.
- Do not put algorithm-specific crypto in AccountLock.
- Do not use argv for PQ proof transport.
- Use CKB2023 spawn + one inherited request pipe.
- Child exit 0 is the only valid proof result.
- Use Type ID for the singleton Account State identity.
- AccountLock args must remain `0x01 || account_id`.
- State deletion must fail.
- All arithmetic/length parsing is checked; no panicking on witness/state input.
- Release builds retain overflow checks.
- No TODOs, placeholder returns or pseudo-code may remain in final implementation.
- Do not call a test passing if cryptography was verified only on the host; final cryptographic tests must execute in CKB-VM.

TOOLCHAIN:
- Rust stable.
- ckb-std 1.1.0.
- ckb-testtool 1.1.1.
- Follow current ckb-script-templates conventions, not deprecated Capsule.

IMPLEMENT IN PHASES:
A. Protocol parser library and unit corpus.
B. Account state resolver + transition validator.
C. CKB sighash and common authorization digest.
D. Spawn/pipe verifier ABI with fixture verifier.
E. P-256 verifier.
F. ML-DSA-65 adapter.
G. SLH-DSA SHA2-128s adapter.
H. full migration/recovery/verifier-upgrade tests.
I. deterministic conformance vector exporter.

REQUIRED TEST STORY:
- Create one account and fund one asset.
- Spend P-256.
- Rotate to P-256+ML-DSA.
- Spend with both.
- Rotate to ML-DSA+SLH-DSA.
- Spend with either when spend threshold is 1.
- Require both for rotation threshold 2.
- Rotate verifier implementation reference.
- Exercise delayed recovery.
- Confirm the asset's AccountLock args are byte-identical at every stage.

REFERENCE INTEGRATIONS:
- Existing `toastmanAu/ckb-mldsa-lock`: use the RustCrypto ML-DSA-65 v2 codebase as an engineering reference. Do not use deprecated v1 logic.
- Nervos `quantum-resistant-lock-script`: use its audited FIPS205 implementation as the SLH-DSA reference. Build an ABI adapter rather than assuming the upstream lock already accepts VerifierRequestV1.

DELIVERABLES:
- all workspace source;
- all tests;
- generated binary conformance vectors;
- cycle report;
- deployment manifest for local/testnet;
- security notes identifying any deviation from upstream verifier implementations;
- README with exact build/test commands.

At the end, run formatting, clippy where applicable, unit tests, ckb-testtool tests, and ckb-debugger checks. Fix all failures. Do not merely describe commands that were not executed.
