# Resumable Real-Testnet Passkey Harness Design

**Date:** 2026-08-25  
**Status:** Approved for implementation planning  
**Target:** Automated local Chromium validation on CKB public testnet

## Purpose

Make the funded Playwright test resumable across browser and test-process exits. The
current real-testnet spec creates its WebAuthn credential in a CDP virtual
authenticator owned by an ephemeral Playwright context. If the test exits after account
bootstrap but before a successful spend, the virtual private key disappears while the
AccountState and AccountLock cells remain live on-chain.

The replacement harness keeps a dedicated Chromium profile and an owner-only backup of
the virtual credential. A failed run can restore the same credential, browser metadata,
and public transaction state rather than creating another account or stranding more
capacity.

This is testnet recovery infrastructure, not a production passkey export format or a
wallet backup feature.

## Incident Being Addressed

The account creation transaction
`0xc5aadcce997ac2eb6329153209032d0a66b86cc5f25ded7335d7d8b7f3dbeceb`
committed successfully. Its 316 CKB AccountState output at index 0 and 200 CKB
AccountLock asset at index 1 remain live. The spend was rejected before tx-pool
acceptance because the client omitted the `send_transaction` outputs validator, causing
the node to apply `well_known_scripts_only` to a custom AccountLock change output.

The validator bug is fixed separately by submitting with `passthrough`. The original
virtual authenticator was destroyed when Playwright exited, so the 516 CKB testnet
account is orphaned. Its public manifest must be archived before a new funded flow.

## Goals

1. Preserve the same virtual WebAuthn credential across test-process exits.
2. Preserve the Chromium profile and browser localStorage until explicit archival or
   removal.
3. Back up the credential before enabling any funded account creation.
4. Resume at the correct stage without duplicate account creation or spend submission.
5. Stop safely when public manifest, credential, browser, or chain state disagree.
6. Retain public account and transaction hashes independently of the browser UI.
7. Provide an explicit, recoverable archive command; never clean up automatically.
8. Keep all private recovery material local, ignored by Git, and inaccessible to other
   local users by default.

## Non-Goals

- Mainnet support.
- Production passkey backup, synchronization, or recovery.
- Exporting a real platform authenticator credential.
- Encrypting recovery state or integrating an operating-system keychain.
- Supporting multiple active accounts or profiles.
- Automatically deleting on-chain cells, local profiles, credentials, or archives.
- Recovering the already orphaned credential from the completed Playwright process.
- Changing AccountLock consensus rules or the AccountState authenticator profile.

## Selected Approach

Use a dedicated persistent Chromium context plus an exported CDP virtual credential.
Chromium profile persistence alone retains localStorage but does not guarantee that a
CDP-created virtual authenticator or its private credential survives a new browser
process. The harness therefore recreates the virtual authenticator on every run and
restores the credential with the CDP WebAuthn API.

A manual system passkey flow remains useful for product demonstrations but is not the
automated conformance path. Its OS and browser integration is not deterministic enough
for the Linux test environment.

## Local State Layout

All private and browser-owned state lives below an ignored local root:

```text
demo/.local/real-testnet/
  active/
    profile/                  Chromium user-data directory
    recovery.json             secret virtual credential + public passkey record
    run.json                  public stage and transaction hashes
  archives/
    <timestamp>-<account-id>/
      profile/
      recovery.json
      run.json
      testnet-account.json
```

`demo/.local/` is ignored as a whole. The active directory is mode `0700`.
`recovery.json` and `run.json` are mode `0600`; Chromium may create profile files with
its own restrictive defaults. No file from this tree is committed or included in the
client bundle.

### Recovery document

`recovery.json` is schema-versioned and contains:

- fixed network `testnet`;
- fixed origin `http://localhost:5173`;
- fixed RP ID `localhost`;
- the validated browser `PasskeyRecord`;
- one CDP WebAuthn credential, including credential ID, RP ID, resident-credential
  flag, user handle, sign count, and P-256 private key;
- creation timestamp.

The CDP credential private key is secret even though it controls testnet value only.
The document is never logged, copied into error messages, returned through the local
API, or exposed to browser application code.

### Run document

`run.json` is schema-versioned public recovery metadata:

- current stage;
- account creation transaction hash when known;
- spend transaction hash when known;
- last successful chain reconciliation time;
- account ID when an active manifest exists.

The run document allows the harness to avoid repeating a mutation after a hash has
already been observed. It must not contain the CKB funding key, WebAuthn private key,
or full recovery document.

## State Classification

The harness classifies disk state before launching Chromium:

| Active manifest | Valid recovery | Meaning | Action |
|---|---|---|---|
| absent | absent | Fresh flow | Permit registration |
| absent | present | Registered but not bootstrapped | Restore and resume account review |
| present | present | Existing recoverable account | Restore and reconcile before mutation |
| present | absent | Orphaned account | Stop before browser mutation |

Malformed recovery, unsafe permissions, symlinks, unsupported schema versions, wrong
origin/RP ID, multiple credentials, or inconsistent credential IDs are blocking
errors. The harness never silently treats invalid recovery state as a fresh flow.

When both manifest and recovery exist, existing client and chain validation remains the
authority for matching the passkey key ID to the AccountState cell. A mismatch blocks
the spend and preserves all state.

## Browser and Authenticator Lifecycle

The real-testnet spec owns a persistent Chromium context instead of using Playwright's
ephemeral `page` fixture.

1. Classify local state.
2. Launch Chromium with `active/profile` as its user-data directory.
3. Enable the CDP WebAuthn domain and create one CTAP2 internal virtual authenticator
   with resident keys, user verification, and automatic presence simulation.
4. If recovery exists, add its credential to the new virtual authenticator before
   loading the application.
5. Restore the validated `PasskeyRecord` into localhost localStorage only when the
   persistent profile lacks it. Conflicting localStorage blocks the run.
6. Load the application after Playwright's `/api/status` readiness check has succeeded.
7. Close the browser context in `finally`; closing preserves the profile and recovery
   files but destroys only the current CDP authenticator instance.

The harness never prints the CDP credential or private key. Persistent state remains
after both successful and failed runs.

## Fresh Registration Flow

For a fresh flow:

1. Require the initial **Create your passkey** stage.
2. Complete registration with the virtual authenticator.
3. Read and validate the public `PasskeyRecord` from localStorage.
4. Retrieve credentials from the CDP authenticator.
5. Require exactly one resident credential for RP ID `localhost`, with a credential ID
   matching the public record.
6. Atomically persist `recovery.json` with owner-only permissions.
7. Re-read and validate the persisted document.
8. Only after persistence succeeds, permit the test to click **Create testnet
   account**.

If any persistence step fails, no CKB transaction is created. The browser profile is
retained for inspection.

## Resumable Stage Flow

The test acts on observed authoritative stages rather than assuming every run starts
from registration:

- **Create your passkey:** allowed only when both manifest and recovery are absent.
- **Create your testnet account:** requires a persisted credential and no manifest.
- **Authorize your first spend:** requires a persisted credential, matching active
  manifest, and successful live-cell preparation.
- **Transaction submitted / confirmation pending:** if a spend hash exists in
  `run.json`, reconcile that transaction only; never call submit again.
- **Spend committed:** verify the committed change and finish without cleanup.

The account creation hash is written to `run.json` immediately after the committed
manifest becomes readable. The spend hash is written immediately after the submitted
receipt becomes observable and before waiting for commitment.

If the known input cell is dead but no spend hash was preserved, the harness stops and
performs read-only reconciliation rather than authorizing a new transaction. The input
outpoint and account manifest provide the forensic starting point.

## Error Handling

Failures report:

- lifecycle stage;
- current visible heading and safe alert text;
- public account creation and spend hashes already known;
- whether the manifest, credential backup, profile, and run metadata were preserved;
- a safe next action: resume, archive, or reconcile.

Failures never report private keys, complete recovery JSON, browser profile contents,
raw environment variables, or unredacted CDP responses.

The harness must distinguish at least:

- API readiness failure;
- recovery file missing, malformed, unsafe, or mismatched;
- browser localStorage conflict;
- virtual authenticator restore failure;
- account bootstrap failure before and after a public hash;
- passkey cancellation;
- witness finalization failure;
- RPC rejection before a hash;
- confirmation timeout after a hash;
- dead or inconsistent live cells.

## Filesystem Safety

- Create private directories with mode `0700`.
- Create recovery and run files with mode `0600`.
- Use same-directory temporary files and atomic rename for JSON replacement.
- Validate the completed file after replacement.
- Use `lstat` and reject symbolic links for active directories and managed files.
- Reject recovery files with group or world permission bits.
- Refuse to overwrite an existing archive directory.
- Never remove active or archived state during normal test execution.

The persistence helper accepts injected paths for tests. Unit tests never operate on
the developer's real `.local/real-testnet` directory.

## Explicit Archive Workflow

Add `npm run testnet:archive`. It is a local, recoverable move operation intended to be
run only after the live test and demo processes have stopped.

The command:

1. Reads and validates any active public account manifest and run metadata.
2. Creates a unique directory below `demo/.local/real-testnet/archives`.
3. Moves the active Chromium profile, recovery, and run metadata into the archive when
   present.
4. Moves `deploy/testnet-account.json` into the same archive when present.
5. Records a public archive summary without credential contents.
6. Leaves on-chain cells unchanged.
7. Refuses collisions and partial-source inconsistencies.

The current orphaned manifest is archived through this workflow even though no
recovery/profile exists. Its archive summary records that the credential is unavailable
and both outputs remain live at the time of archival.

Archive is not deletion. Permanent deletion of a profile or recovery credential is a
separate manual action that must identify the account explicitly. No package script or
test cleanup deletes credentials automatically.

## Security Boundaries

- The feature is gated by `RUN_CKB_TESTNET=1`, a valid testnet-only `CKB_PRIVKEY`, and
  the existing internal real-testnet spec marker.
- `CKB_PRIVKEY` stays environment-only in the Node backend and is never written to the
  recovery tree.
- Recovery is fixed to CKB testnet, localhost origin, and RP ID `localhost`.
- Recovery helpers live in test-only modules and cannot enter the production client
  bundle.
- The browser receives only the existing public API data.
- The credential backup is plaintext by design for deterministic local recovery; its
  protection is local filesystem ownership and Git exclusion. Documentation must call
  this out clearly.
- A recovered credential can authorize the associated remaining testnet AccountLock
  capacity. Anyone who copies it has that capability.

## Proposed Code Boundaries

- `demo/test/support/real-testnet-state.ts`
  - schemas, state classification, permission checks, atomic persistence, restore data,
    and archive primitives;
- `demo/test/support/archive-real-testnet.ts`
  - command entry point for the explicit archive workflow;
- `demo/test/browser/real-testnet.spec.ts`
  - persistent context, CDP authenticator lifecycle, stage-aware orchestration, public
    hash capture, and read-only reconciliation decisions;
- `demo/test/server/real-testnet-state.test.ts`
  - filesystem, state matrix, recovery validation, and archive tests using temporary
    directories;
- `demo/.gitignore` or repository `.gitignore`
  - ignore `demo/.local/`;
- `demo/package.json`
  - add the explicit `testnet:archive` command;
- `demo/README.md`
  - document recovery sensitivity, resume behavior, archival, and permanent-removal
    warning.

Exact boundaries may be adjusted during planning if existing test utilities provide a
clearer home, but recovery code must remain outside the production client graph.

## Verification Strategy

### Test-driven unit coverage

Write failing tests first for:

- all four manifest/recovery state combinations;
- unsupported version, network, origin, RP ID, credential count, and credential-ID
  mismatch;
- atomic round-trip persistence;
- `0700` directory and `0600` file permissions;
- rejection of symlinks and unsafe permission bits;
- restoration payload fidelity without logging private material;
- archive of complete active state;
- archive of the current orphaned-manifest shape;
- collision and partial-failure refusal;
- stage decisions that prohibit duplicate bootstrap and duplicate submission.

### Existing deterministic checks

The complete `npm run check` gate must continue to pass:

- TypeScript client and Node type checks;
- all Vitest unit and component tests;
- all deterministic Playwright browser flows;
- production Vite build;
- client bundle boundary audit.

### Live verification

After deterministic checks pass:

1. Archive the current orphaned manifest.
2. Start one new funded real-testnet run with the persistent harness.
3. Confirm `recovery.json` exists with restrictive permissions before bootstrap.
4. Confirm account creation commits and `run.json` records its hash.
5. Confirm the spend is accepted with `passthrough` and its hash is recorded before
   confirmation.
6. Confirm the spend commits and the live AccountLock change matches the receipt.
7. Stop and restart the harness in a read-only/resume mode to prove the credential and
   profile remain recoverable without creating another transaction.
8. Retain the active state until the user explicitly archives it.

## Acceptance Criteria

The work is complete when:

- no funded account can be created before its virtual credential backup is durably
  validated;
- a post-bootstrap test failure can restore the same passkey on the next process run;
- manifest-without-credential state blocks before mutation;
- known transaction hashes prevent duplicate mutations;
- local credential material is ignored, owner-only, schema-validated, and never logged;
- the current orphaned manifest is preserved in a recoverable archive;
- deterministic verification passes;
- one fresh funded flow creates, spends, commits, and retains recoverable local state;
- no automatic cleanup removes the profile, credential, manifest, hashes, or archives.
