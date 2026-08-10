# Reference Implementation Specification v0.1

## Goal

Produce the first executable reference implementation of the crypto-agile CKB account protocol. The implementation must prove that a single asset lock identity can survive:
1. P-256 passkey authorization,
2. hybrid P-256 + ML-DSA authorization,
3. post-quantum ML-DSA + SLH-DSA authorization,
4. verifier implementation rotation,
without rewriting `AccountLock.args`.

## Hard protocol inputs

The coding agent MUST treat the following files/RFCs as normative and must not redesign them:
- AccountLockV1: 33-byte args `0x01 || account_id`.
- AccountStateV1: `CKAS`, 32-byte header, sorted variable authenticator entries.
- AccountWitnessV1: `CKAW`, sorted proof entries.
- Account Authorization Digest v1: `CKB_HASH("CKB_ACCOUNT_LOCK_V1" || operation || account_id || sequence || state_data_hash || group_sighash)`.
- Verifier ABI v1: `CKVR`, 96-byte fixed header + aux + proof.
- Algorithms: P-256/WebAuthn, ML-DSA-44/65/87, SLH-DSA/FIPS205.
- Weighted thresholds for SPEND, ROTATE and RECOVERY.

## Repository architecture

### `crates/protocol`
No-std pure parsing/constants shared by on-chain and host tests.
It MUST contain no transaction syscalls and no cryptographic implementation.
All parsers are bounded and zero-copy where practical.

### `contracts/account-lock`
Small durable policy engine.
Responsibilities:
- load script args and account_id;
- infer/validate operation from AccountWitness;
- resolve current Account State;
- validate canonical state;
- validate transition for ROTATE/RECOVERY;
- build canonical group sighash;
- build common authorization digest;
- map proof slot -> state authenticator;
- resolve verifier CellDep exactly;
- spawn verifier sequentially and send ABI request;
- add weight only on exit code 0;
- enforce operation threshold.

It MUST NOT contain P-256, ML-DSA or SLH-DSA cryptography.

### `contracts/verifier-p256`
Native verifier implementing ABI v1 and the frozen WebAuthn profile.
Use raw P-256/ES256 verification with the exact RP/origin/UP/UV rules.
The 32-byte ABI authorization digest is the WebAuthn challenge.

### `contracts/verifier-mldsa-adapter`
First implementation target is ML-DSA-65 RustCrypto-compatible semantics.
Do NOT copy the older deprecated v1 witness-coverage behavior.
The adapter receives the Account ABI digest rather than rebuilding CighashAll.
Where possible, extract/reuse only audited/reviewed primitive verification code from the existing v2 project.

### `contracts/verifier-slhdsa-adapter`
First implementation profile targets the audited Nervos mainnet FIPS205 all-in-one verifier semantics.
Prefer a thin adapter or shared verifier core rather than forking the entire upstream lock.
The account state's SLH suite byte is mandatory and must select the exact parameter set.

### `crates/host`
Reference host/wallet library.
It must produce byte-identical state, witnesses, group sighash, authorization digest, and verifier proof payloads.
This is the place for platform WebAuthn bridges and PQ signing helpers.

### `tests`
Use `ckb-testtool` for all CKB-VM consensus tests and `ckb-debugger` for release-vector cross-checks.

## Dependency baseline

Reference baseline as of 2026-08-10:
- `ckb-std = 1.1.0`
- `ckb-testtool = 1.1.1`
- CKB Rust family compatible with 1.1 testtool.
Do not use Capsule; bootstrap/build conventions should follow current CKB script templates.

Pin exact versions in the final lockfile before publishing test vectors.

## Account State identity

Use built-in CKB Type ID for the singleton Account State Cell.

Creation test:
- create Type ID cell,
- calculate full Type Script hash,
- set this 32-byte hash as `account_id`,
- state cell lock = AccountLock(account_id),
- asset cell lock = AccountLock(account_id).

State update:
- one Account State input,
- exactly one successor output with identical full Type ID Script,
- sequence + 1.

State deletion must fail.

## Current-state resolution

### SPEND
State is supplied by CellDep:
- exactly one dep has type hash == account_id;
- its data is current state;
- state cell must not simultaneously appear as an input;
- witness sequence equals state sequence.

### ROTATE / RECOVERY
State is an input:
- exactly one input has type hash == account_id;
- exactly one output has identical full Type ID Script;
- output sequence = input sequence + 1.
Do not require the state to also be provided as a dep.

## Threshold validation

Before accepting state:
- authenticators sorted strictly by slot;
- no duplicate slots;
- count 1..16;
- all weights >= 1;
- only known capability bits;
- every enabled threshold > 0;
- each threshold <= sum(weight of authenticators with that capability);
- RECOVERY threshold must be zero when recovery disabled and >0 when enabled;
- no arithmetic overflow.

For proof accounting:
- proof slots sorted strictly;
- slot must exist;
- slot must have operation capability;
- each slot counted at most once;
- child exit code must equal zero before weight is added.

## Canonical group sighash

Implement once in a shared on-chain module and once independently in host code.

For the first group witness:
- parse WitnessArgs;
- preserve input_type and output_type;
- replace lock with explicitly present empty Bytes, not None;
- Molecule serialize the canonical WitnessArgs.

Hash:
- raw transaction hash;
- canonical first group witness length+bytes;
- remaining same-lock-group witness length+bytes;
- extra witnesses beyond input count length+bytes.

Use CKB default hash.

Create differential tests proving host and VM derive the same group_sighash.

## Verifier ABI transport

Use CKB2023 spawn.

Parent flow:
1. resolve matching verifier CellDep by configured data/type hash;
2. create pipe;
3. spawn dep cell DATA with 4 MiB child memory;
4. inherit only request read fd;
5. parent writes exactly one VerifierRequestV1;
6. close writer;
7. wait;
8. exit 0 = valid; any other code = invalid.

Do not use argv for proof payload.
Do not add a response pipe.
Do not parallelize verifiers in v1.

## Verifier adapter proof formats

The exact inner proof formats should be separately versioned but remain opaque to AccountLock.

### P256ProofV1
Reuse frozen Passkey witness fields minus duplicated state commitments:
- public_key [65]
- origin_len u8 + origin
- authenticator_data_len u16 + bytes
- client_data_json_len u16 + bytes
- signature_len u16 + strict DER bytes

The verifier gets rp_id_hash/origin_hash from ABI `aux`.
Require `CKB_HASH(public_key) == key_id` full 32 bytes.

### MLDSAProofV1
Recommended:
- proof_version u8 = 1
- public_key_len u16
- signature_len u16
- public_key
- signature

Algorithm ID determines 44/65/87.
Verifier profile determines RustCrypto/fips204 message semantics.
For the first reference profile use ML-DSA-65 RustCrypto.

### SLHDSAProofV1
Recommended:
- proof_version u8 = 1
- public_key_len u16
- signature_len u16
- public_key
- signature

Suite comes only from AccountState aux; proof may not override it.
The first profile targets the Nervos all-in-one FIPS205 verifier.

## Mandatory staged tests

### T00 Parsing
All RFC structural vectors pass.
All malformed-length/reserved-bit/sorting cases fail.

### T01 Create account
Create Type ID Account State with P-256 signer.
Derive account_id.
Create independent asset cell using AccountLock(account_id).

### T02 P-256 spend
Spend asset with SPEND threshold 1.
State provided as CellDep.
AccountLock args unchanged in successor asset.

### T03 Rotate to hybrid
Consume state and create successor:
- slot 1 P-256 weight 1 SPEND|ROTATE
- slot 2 ML-DSA-65 weight 1 SPEND|ROTATE
- spend_threshold=2
- rotate_threshold=2
Sequence increments exactly once.

### T04 Hybrid spend
Same asset identity; both child verifiers exit 0.
Removing either proof fails threshold.

### T05 Rotate to PQ-diverse
Successor:
- ML-DSA-65
- SLH-DSA-SHA2-128s
Recommended:
- spend_threshold=1
- rotate_threshold=2
This demonstrates convenient PQ spending with two-family control over account mutation.

### T06 ML-DSA spend
Only ML-DSA proof.
Same AccountLock args.

### T07 SLH-DSA spend
Only SLH proof.
Same AccountLock args.

### T08 PQ rotation threshold
Attempt state modification with only one PQ family -> fail.
Both ML-DSA + SLH-DSA -> pass.

### T09 Verifier upgrade
Change ML-DSA VerifierRef while keeping:
- account_id
- ML-DSA key_id
- algorithm ID
unchanged.
Then spend successfully using new implementation.

### T10 Recovery delay
Configure SLH signer as RECOVERY.
Verify transaction before since threshold fails and after threshold succeeds.

### T11 State deletion
Consume Account State without successor -> fail.

### T12 State substitution
Use another valid Account State cell with different Type ID -> fail.

### T13 Digest mutation
For each authenticator family independently mutate:
- capacity,
- output lock,
- output type,
- output data,
- since,
- cell dep,
- group witness,
- extra witness.
Old proof must fail.

## Real-network integration fixtures

### ML-DSA testnet reference
Use `mldsa65-lock-v2-rust` as the initial cryptographic source/reference:
- code_hash: `0xd70653f7fd51e173ec506b76081f37bf4acebb8a15dc79e6d4ad43ca4d3b78a4`
- hash_type: type
The existing project has signed round-trip testnet spends and is not audited; use it as a testnet engineering reference, not as an audit substitute.

### SLH-DSA reference
Use Nervos `quantum-resistant-lock-script` as the first FIPS205 reference:
- mainnet code_hash: `0x302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf`
- testnet code_hash: `0x147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf`
- first wallet suite: SLH-DSA-SHA2-128s
The upstream repository documents a ScaleBit audit.

Do not directly point the Account Verifier ABI at an upstream lock unless its executable entry point actually implements ABI v1. Build a thin adapter or factor out its verifier core.

## Release gates

The reference implementation is complete only when:
- all tests run in CKB-VM, not mocked host crypto;
- testtool and debugger agree;
- exact positive and negative binary vectors are emitted;
- cycle counts are captured per test;
- AccountLock binary contains no algorithm-specific crypto;
- same asset AccountLock args survive all staged migrations;
- verifier failure cannot partially count weight;
- all integer parsing and length arithmetic are checked;
- overflow-checks remain enabled in release;
- fuzz corpus is retained in repo;
- no mainnet deployment is recommended until independent security review.
