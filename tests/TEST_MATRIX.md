# Required CKB-VM Test Matrix

T01 through T10 are exercised as one ordered scenario by
`story::complete_crypto_migration_recovery_and_verifier_upgrade_story_runs_in_ckb_vm`.
The story executes Type ID creation and registers each verified successor under
its real transaction outpoint before the next transaction consumes or references
it. The originally funded asset outpoint is likewise carried through every
spend. It asserts the same `0x01 || account_id` lock args at every asset/state
output. Focused negative and parser-corpus tests cover the remaining rows.

| ID | Test | Expected |
|---|---|---|
| T00 | State/witness/ABI parsing corpus | exact pass/fail |
| T01 | Create Type-ID account and asset | pass |
| T02 | P-256 spend | pass |
| T03 | Rotate P-256 -> P-256+ML-DSA | pass |
| T04 | Hybrid spend with both proofs | pass |
| T04a | Hybrid spend missing P-256 | fail |
| T04b | Hybrid spend missing ML-DSA | fail |
| T05 | Rotate -> ML-DSA+SLH-DSA | pass |
| T06 | ML-DSA spend, threshold 1 | pass |
| T07 | SLH-DSA spend, threshold 1 | pass |
| T08a | Rotate with ML-DSA only, threshold 2 | fail |
| T08b | Rotate with SLH only, threshold 2 | fail |
| T08c | Rotate with both | pass |
| T09 | VerifierRef upgrade | pass |
| T10a | Recovery before since | fail |
| T10b | Recovery after since | pass |
| T11 | State deletion | fail |
| T12 | Foreign state substitution | fail |
| T13 | Transaction mutation per field/family | fail |
| T14 | Duplicate proof slot | fail |
| T15 | Nonzero verifier exit contributes weight | fail |
| T16 | Unknown ABI/algorithm/flags | fail |

## Verifier ABI v1 cross-package conformance

`crates/host/tests/abi_v1_conformance.rs` checks this implementation against the
frozen `ckb-account-verifier-abi-v1` vector set, mirrored under
`vectors/abi-v1/` (see its `PROVENANCE.md`). These rows guard the wire format
against silent drift between the RFC package and this repository.

| ID | Test | Expected |
|---|---|---|
| A00 | `encode_verifier_request` vs `ABI-V1-STRUCT-001.request_hex` | byte-identical |
| A01 | Framing parse of `ABI-V1-STRUCT-001` + field recovery | accept, fields match |
| A02 | Eleven framing mutations (NEG-001..010, NEG-016) | reject |
| A03 | Every published negative vector is classified | fail on unclassified vector |

Five published mutations are cross-checks the framing parser provably cannot
own, and are deferred with a recorded reason in `DEFERRED_MUTATIONS` rather than
asserted at the wrong layer:

| Vector | Mutation | Owning layer |
|---|---|---|
| NEG-011 | `slot` | AccountLock request construction (copies `AuthenticatorEntryV1::slot`) |
| NEG-012 | `algorithm` | AccountState cross-check; parser does not receive the entry |
| NEG-013 | `key` | verifier cryptography — ABI exit 5 `KEY_ID_MISMATCH` |
| NEG-014 | `digest` | verifier cryptography — ABI exit 1 `INVALID_PROOF` |
| NEG-015 | `profile` | per-algorithm verifier dispatch — ABI exit 4 `UNSUPPORTED_PROFILE` |

Note that `ABI-V1-STRUCT-001` carries a placeholder proof
(`"example-passkey-proof"`), so its declared expectation is `accept_structure`,
not `accept`. Asserting a verifier binary rejects NEG-013/014 would be vacuous,
because the same verifier also rejects the unmutated base. Closing those rows
requires a cryptographically real base vector, which is upstream work in the ABI
package.
