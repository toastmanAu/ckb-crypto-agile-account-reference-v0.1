# Deployment guide

No AccountLock or adapter artifact from this repository is currently claimed
as deployed on testnet or mainnet. The references in
`deploy/reference-deployments.json` are either local artifact identities or
explicitly labeled upstream engineering references.

## 1. Build and validate

Follow `REPRODUCIBLE_BUILDS.md`, then run:

```sh
./scripts/check.sh
```

Record the exact source commit and CKB data hash of every release ELF. Do not
substitute a debug binary or an ELF built from a dirty checkout.

## 2. Publish code cells

Publish separate code cells for:

- AccountLock
- WebAuthn ES256/P-256 verifier
- ML-DSA-65 verifier adapter
- SLH-DSA SHA2-128s verifier adapter

These scripts use CKB2023 spawn behavior. When addressed by data hash, use the
CKB2023-compatible `data2` script hash type. A verifier reference stored in
AccountStateV1 must match the exact deployed hash, hash-type selector, ABI
version, and algorithm profile.

The fixture verifier exists only for ABI tests and should not authorize a
deployed account.

## 3. Create the singleton Account State

Account state identity is the built-in CKB Type ID script. For a creation
transaction whose state is output index `i`, compute its 32-byte Type ID args as:

```text
CKB_HASH(first_input_serialized || i_le_u64)
```

The account ID is the resulting full Type ID script hash:

```text
account_id = CKB_HASH(type_id_script_serialized)
```

Every protected asset uses AccountLock args:

```text
0x01 || account_id
```

The initial AccountStateV1 must use sequence 0, sorted unique authenticator
slots, satisfiable spend/rotation thresholds, and a consistent recovery flag,
threshold, and `since` value.

Create and fund assets in the same transaction or a later transaction. The VM
story in `tests/src/story.rs` demonstrates creation in one transaction and then
carries the exact state and asset outpoints through the lifecycle.

## 4. Construct operations

### Spend

- Include exactly one matching state cell dep.
- Do not consume any cell with the account's Type ID.
- Add verifier code deps for every supplied proof.
- Satisfy the state's spend threshold with `CAP_SPEND` entries.

### Rotation

- Consume exactly one matching state input.
- Create exactly one state output with the identical full Type ID script.
- Increment sequence by exactly one.
- Authorize against the current state and rotation threshold, not the successor.

### Recovery

- Apply all rotation transition rules.
- Require recovery to be enabled.
- Set the state input `since` to at least the current state's recovery value.
- Satisfy the current recovery threshold with `CAP_RECOVERY` entries.

In all cases, construct proof slots in strictly increasing order and compute
the final proof payloads from the common authorization digest produced by the
host helpers.

## 5. Record a network manifest

For every deployed program, record:

- network and genesis hash
- deployment transaction hash and output index
- dep type
- script hash type
- code/data hash
- ELF byte length
- source commit
- build toolchain
- verifier algorithm/profile and ABI version

Do not overwrite an existing immutable deployment entry when upgrading a
verifier. Add a new entry, rotate AccountStateV1 through the currently
authorized threshold, and retain enough historical metadata to reconstruct
old transactions.

## 6. Post-deployment validation

- Fetch deployed cell data and compare it byte-for-byte with the release ELF.
- Recompute every CKB data hash.
- Run positive and negative transactions against a local node or testnet.
- Confirm AccountLock args remain `0x01 || account_id` after rotation/recovery.
- Confirm a nonzero child exit never contributes weight.
- Measure cycles using the exact deployed verifier combination.
- Obtain independent review before protecting material value.
