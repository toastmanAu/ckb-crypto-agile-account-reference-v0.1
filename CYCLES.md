# CKB-VM cycle report

Measured on 2026-08-10 with optimized `riscv64imac-unknown-none-elf` binaries,
CKB2023 scripts (`data2`), `ckb-testtool` 1.1.1, and the deterministic tests in
`tests/src/lib.rs`.

| Path | Cycles |
|---|---:|
| Fixture spawn/pipe spend | 187,707 |
| WebAuthn ES256/P-256 spend | 6,157,249 |
| ML-DSA-65 spend | 14,007,568 |
| SLH-DSA SHA2-128s spend | 21,051,851 |

The standalone `ckb-debugger` replay of `vectors/fixture-spend.json` returned
exit code 0. Its pre-gather total was 187,707 cycles and actual-run total was
60,078 cycles. Cycle numbers are reference measurements, not consensus limits;
transaction builders must budget for the selected verifier set and proof count.
The cryptographic test APIs may randomize signatures, so instruction paths and
reported totals can vary slightly between runs; the table records the final
validation run rather than a protocol constant.
