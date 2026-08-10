# Required CKB-VM Test Matrix

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
