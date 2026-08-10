# Implementation Order

1. `crates/protocol`: finish strict state/witness/request parsers and exhaustive unit tests.
2. Build `account-lock` with a temporary deterministic test verifier returning valid only for fixed fixtures.
3. Prove SPEND/ROTATE/RECOVERY state resolution and weighted policy without crypto.
4. Implement canonical sighash and authorization digest; generate VM/host differential vectors.
5. Implement spawn/pipe ABI parent and tiny fixture child verifier.
6. Implement P-256 child and port Passkey vectors.
7. Adapt ML-DSA-65 RustCrypto verification.
8. Adapt SLH-DSA SHA2-128s verification.
9. Run the complete staged migration suite.
10. Only then add native wallet WebAuthn/PQ signing UX and deployment scripts.

Do not start with UI. Do not merge cryptographic code into AccountLock to save time.
