# Code-cell deployment tooling

Publishes this repository's release ELFs as immutable CKB code cells and records
their outpoints.

This package is deliberately **outside the Rust workspace**. It needs network
access and a signing key, neither of which `scripts/check.sh` should ever
require, and it must not be able to perturb the pinned dependency graph or the
reproducible release ELFs.

## Prerequisites

Build the release artifacts first — the tool refuses to publish anything whose
data hash does not match `deploy/reference-deployments.json`:

```sh
cd ../.. && ./scripts/check.sh
```

Then install:

```sh
npm install
```

## Dry run

The default is a dry run. It touches no network and needs no key:

```sh
npm run plan              # phased: AccountLock + P-256 verifier
npm run plan -- --all     # all four artifacts
```

| Selection | Cells | Capacity |
|---|---:|---:|
| Phased (`account_lock`, `verifier_p256`) | 2 | ~95,690 CKB |
| All (`--all`) | 4 | ~179,092 CKB |

Capacity is `8 + 33 + lock_args + data` bytes at 1 CKB per byte, plus fees.

## Publishing

```sh
CKB_PRIVKEY=0x... npm run deploy -- --broadcast
CKB_PRIVKEY=0x... npm run deploy -- --broadcast --all
```

The key is read from the environment and never logged. One transaction is sent
per artifact, so a partial failure still leaves unambiguous outpoints for
whatever landed. Results are written to `deploy/testnet-deployments.json`.

### What is checked, and when

| Stage | Check |
|---|---|
| Before building any transaction | every artifact's data hash matches the recorded identity |
| Before broadcasting | wallet balance covers total planned capacity |
| After commitment | the published cell is re-read and its on-chain data hash re-verified |

A code cell cannot be edited after publication, so the pre-flight hash check has
no second chance. Publishing a debug build or an ELF from a dirty checkout would
produce a cell that no `AuthenticatorEntryV1` VerifierRef can resolve.

## Cell locks and reclaiming capacity

Published cells carry the deployer's own lock, so the capacity is reclaimable by
consuming them. **Consuming a published code cell breaks every dep reference to
it.** For a durable deployment, either leave these cells untouched or move them
under an unspendable lock.

## Hash type

These are plain data cells addressed by data hash, so accounts reference them
with `hash_type: "data2"` and `verifier_hash_type: 0x00`. That makes each
verifier immutable, matching the frozen-v1 rule in the root README: a new
verifier implementation is a new code cell and a `VerifierRef` rotation, never
an in-place edit.

## Dependency posture

`@ckb-ccc/core` is the only runtime dependency. `npm audit` reports four `low`
advisories reaching it transitively through `@joyid/ckb` →
`@nervosnetwork/ckb-sdk-utils` → `elliptic`. This tool signs with
`SignerCkbPrivateKey` and never constructs a JoyID signer, so that path is not
exercised here. The advisories are recorded rather than suppressed; re-check
with `npm audit` before any deployment carrying real value.

`package-lock.json` is committed. Install with `npm ci` for a reproducible
toolchain, and prefer `--ignore-scripts`.
