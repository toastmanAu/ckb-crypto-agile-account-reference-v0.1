# ABI v1 conformance vectors — provenance

These files are a verbatim mirror of the `vectors/` directory of the
`ckb-account-verifier-abi-v1` package, which freezes the consensus-candidate
interface between AccountLockV1 and algorithm verification programs
(`CKB-Account-Verifier-ABI-v1-RFC-v0.5`).

They are mirrored rather than referenced so that this repository's test gate is
hermetic: CI checks out only this repository, and a conformance test that
silently skips when its data is missing is worse than no test at all.

| | |
|---|---|
| Source package | `ckb-account-verifier-abi-v1` |
| Mirrored on | 2026-08-15 |
| Files | 1 positive structural vector, 16 named mutation vectors |

## Consumed by

`crates/host/tests/abi_v1_conformance.rs`, which runs as part of
`./scripts/check.sh` and CI. It asserts that:

1. `encode_verifier_request` reproduces `ABI-V1-STRUCT-001.request_hex`
   byte-for-byte;
2. `VerifierRequest::parse` accepts that vector and recovers every declared
   field;
3. `VerifierRequest::parse` rejects all eleven framing mutations; and
4. every published negative vector is classified as either framing-owned or
   explicitly deferred — so a newly published vector fails the build instead of
   being ignored.

## Updating

The upstream package is the normative source. To refresh:

```sh
cp ../ckb-account-verifier-abi-v1/vectors/*.json vectors/abi-v1/
( cd vectors/abi-v1 && sha256sum *.json > SHA256SUMS )
cargo test --locked -p ckb-account-host --test abi_v1_conformance
```

Verify the mirror is unmodified with:

```sh
( cd vectors/abi-v1 && sha256sum --check SHA256SUMS )
```

If a refresh changes `ABI-V1-STRUCT-001.request_hex`, the wire format itself has
moved. That is a protocol-version event under the freeze rule in the README —
it must not be absorbed by editing this implementation to match.
