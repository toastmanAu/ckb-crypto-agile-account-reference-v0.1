# Passkey Frontend Demo Design

**Date:** 2026-08-23  
**Status:** Approved for implementation planning  
**Target:** Local Chromium on CKB public testnet

## Purpose

Build a local end-to-end demonstration of the deployed crypto-agile AccountLock and
WebAuthn ES256/P-256 verifier. A user creates a passkey, creates and funds an account,
then authorizes a real CKB testnet spend through the browser. The resulting transaction
must execute the published AccountLock and P-256 verifier code cells on-chain.

The demo is a protocol proof, not a general-purpose wallet. It deliberately targets one
browser, one origin, one authenticator, one account state, and one transaction shape.

## Success Criteria

The demo is complete when a user can:

1. Start a localhost-only backend with a funded testnet `CKB_PRIVKEY` in its environment.
2. Open the React application in Chromium at `http://localhost:5173`.
3. Create an ES256 passkey scoped to RP ID `localhost`.
4. Bootstrap a singleton AccountStateV1 cell and a 200 CKB AccountLock asset cell.
5. Review a transaction that sends 100 CKB back to the backend funder and returns the
   remaining capacity, minus fees, to the passkey account.
6. Authorize the spend with the passkey.
7. See the transaction commit and open it in the CKB testnet explorer.

Success requires byte-for-byte agreement between the browser protocol codec and the
Rust host helpers. A UI-only simulation or a backend-signed AccountLock spend does not
satisfy the goal.

## Non-Goals

- Mainnet support.
- Safari or Firefox support.
- A production deployment or remote backend.
- Multiple accounts, passkeys, authenticators, or browser profiles.
- Account rotation, recovery, session keys, ML-DSA, or SLH-DSA.
- Arbitrary recipient addresses or transfer amounts.
- Private-key import or general wallet functionality in the browser.
- Automatic account deletion or reset.
- Hiding that the software is an unaudited testnet reference implementation.

## Fixed Environment

| Setting | Value |
|---|---|
| Network | CKB public testnet |
| Browser | Current Chromium/Chrome |
| Client origin | `http://localhost:5173` |
| WebAuthn RP ID | `localhost` |
| WebAuthn algorithm | ES256 (`-7`) |
| User verification | Required |
| Backend bind address | `127.0.0.1` only |
| Initial AccountLock asset | 200 CKB |
| Demonstration transfer | 100 CKB to the backend funder |
| AccountLock hash type | `data2` |
| Verifier hash type | `data` reference in AccountStateV1, resolved from a `data2` code cell |

The RP ID and origin hashes are consensus-relevant account-state data. Changing either
value requires creating a different account.

## Architecture

Add a self-contained `demo/` TypeScript application with three boundaries.

### `demo/client`

A React/Vite single-page application responsible for:

- WebAuthn feature detection and passkey registration.
- Converting the registration SPKI public key to canonical 65-byte uncompressed P-256.
- Persisting non-secret credential metadata locally.
- Reading deployment and account status through the localhost API.
- Discovering the current live AccountLock asset through CCC.
- Building the raw spend transaction in the browser.
- Adding AccountLock, verifier, and state cell dependencies.
- Computing the canonical group sighash and authorization digest.
- Requesting a WebAuthn assertion with that digest as the challenge.
- Encoding P256ProofV1 and AccountWitnessV1.
- Submitting the transaction and waiting for commitment.
- Presenting explorer links and actionable errors.

The client must never receive the funding private key or ask the backend to sign the
AccountLock spend.

### `demo/server`

A localhost-only Node/TypeScript API responsible for:

- Reading `CKB_PRIVKEY` from the server process environment.
- Deriving and reporting only the funder address and public balance.
- Verifying the recorded code-cell deployment manifest.
- Validating public passkey account configuration.
- Invoking the Rust AccountStateV1 exporter for consensus-exact state bytes.
- Constructing, signing, broadcasting, and confirming the one-time bootstrap transaction.
- Persisting and serving `deploy/testnet-account.json`.
- Returning structured, redacted failure responses.

Bootstrap logic should be extracted from the existing deployment tool into importable,
dependency-injected functions rather than duplicated or invoked through an opaque shell
command. The Rust exporter remains the authority for initial state serialization.

### `demo/shared`

Browser-safe modules responsible for:

- API request and response schemas.
- Deployment and account manifest validation.
- Byte and integer encoding helpers.
- P256ProofV1 and AccountWitnessV1 encoding.
- CKB group sighash and authorization-digest construction.
- Capacity and fee calculations used by the fixed spend flow.

The shared codec is a narrow TypeScript port of the required `crates/host` behavior. It
must not become a second informal protocol specification; exported Rust vectors define
its accepted behavior.

## User Experience

The interface is a three-step wizard with one primary action per step.

### Persistent status header

Show the following as secondary status, without competing with the active step:

- CKB testnet.
- Client origin and RP ID.
- Local API connectivity.
- AccountLock and P-256 deployment verification.
- Backend funder address and balance.
- An explicit “unaudited testnet software” label.

### Step 1: Create passkey

The primary action is **Create passkey**. Before enabling it, the client verifies:

- It is running in a secure WebAuthn context accepted for localhost.
- `PublicKeyCredential` is available.
- Chromium can return the registration public key.
- No incompatible credential metadata already exists locally.

Registration uses ES256, resident-key preference, and required user verification. The
client displays the derived key ID after success but does not present low-level
attestation data by default.

### Step 2: Create account

The primary action is **Create testnet account**. The review shows:

- The passkey key ID.
- The AccountLock and P-256 code hashes.
- A 200 CKB AccountLock asset.
- The backend funder address.
- The expected one-time capacity use.

The backend returns the committed account ID, state outpoint, asset outpoint, and an
explorer link. If an account manifest already exists, the API returns that manifest and
does not broadcast again.

### Step 3: Authorize spend

The primary action is **Authorize 100 CKB spend**. The review shows:

- Input AccountLock asset and capacity.
- 100 CKB destination to the funder address.
- AccountLock change capacity.
- Estimated fee.
- All code and state dependencies.

After the passkey assertion and submission, the page shows submitted and committed
states separately. The final receipt includes the transaction hash, explorer link, and
remaining AccountLock capacity.

## Passkey Registration Data Flow

1. The client generates a random user handle and challenge for registration.
2. It calls `navigator.credentials.create()` with RP ID `localhost`, ES256, and required
   user verification.
3. It obtains the credential ID and SPKI public key from the attestation response.
4. WebCrypto imports the SPKI key and exports it in raw uncompressed form.
5. The client requires exactly 65 bytes beginning with SEC1 tag `0x04`.
6. It computes `key_id = CKB_HASH(public_key)` using CKB's personalized Blake2b hash.
7. It computes:
   - `rp_id_hash = SHA-256("localhost")`
   - `origin_hash = SHA-256("http://localhost:5173")`
   - `aux = 0x01 || rp_id_hash || origin_hash`
8. It stores credential ID, public key, key ID, RP ID, origin, and schema version in
   browser storage. None of these values are secret.

The account configuration uses one authenticator at slot 0 with algorithm 1, weight 1,
and SPEND, ROTATE, and RECOVERY capabilities. All thresholds are 1 and sequence is 0,
matching the current example configuration.

## Bootstrap Data Flow

1. The client posts its public account configuration to the local API.
2. The server validates every fixed field and recomputes key ID, RP ID hash, origin hash,
   and aux rather than trusting derived values from the browser.
3. The server writes a short-lived configuration in a restricted temporary directory.
4. The Rust exporter produces AccountStateV1 bytes. The server validates non-empty
   output and removes temporary material after use.
5. Refactored bootstrap logic verifies deployed code hashes and constructs a Type ID
   state output plus a 200 CKB AccountLock asset output.
6. The backend signer collects inputs, patches Type ID and AccountLock args, completes
   the fee, runs creation-consistency checks, broadcasts, and waits for commitment.
7. It atomically writes `deploy/testnet-account.json` and returns its public contents.

The endpoint is idempotent. Once the account manifest exists, a request with different
passkey material fails with an account-mismatch error rather than creating another
account.

## Spend Transaction Data Flow

1. The client validates deployment and account manifests.
2. It resolves the singleton state cell and verifies its type script, AccountLock, and
   data against the manifest and expected account ID.
3. It scans live cells by the account lock, excludes typed state cells, and selects the
   single capacity-only asset cell. Ambiguous multiple assets fail closed in version one.
4. It builds one AccountLock input and two outputs:
   - 100 CKB under the backend funder's standard lock.
   - Remaining input capacity minus a conservatively calculated fee under the unchanged
     AccountLock.
5. It adds exactly these cell deps:
   - Published AccountLock code-cell outpoint.
   - Published P-256 verifier code-cell outpoint.
   - Singleton AccountStateV1 outpoint.
6. It adds a valid packed WitnessArgs with an empty lock field.
7. From the raw transaction hash and canonicalized witnesses, it computes the group
   sighash. Canonicalization replaces the first group witness lock with empty bytes, so
   the variable DER signature length does not change the authorization digest.
8. It computes:

   ```text
   CKB_HASH(
     "CKB_ACCOUNT_LOCK_V1" ||
     OP_SPEND ||
     account_id ||
     sequence_le_u64 ||
     CKB_HASH(current_state_bytes) ||
     canonical_group_sighash
   )
   ```

9. It passes the 32-byte digest directly as the WebAuthn assertion challenge and
   restricts `allowCredentials` to the registered credential ID.
10. It requires required user verification and validates the returned credential ID.
11. It encodes P256ProofV1 as:
    - public key `[65]`
    - origin length `u8` and origin bytes
    - authenticator-data length `u16le` and bytes
    - client-data-JSON length `u16le` and bytes
    - DER-signature length `u16le` and bytes
12. It wraps the proof at slot 0 in AccountWitnessV1 for OP_SPEND and sequence 0, places
    it in the first WitnessArgs lock field, and leaves raw transaction fields unchanged.
13. It submits the transaction through CCC, reports the hash immediately, waits for
    commitment, then re-scans the resulting AccountLock change.

## Capacity and Fee Policy

The flow has one fixed 200 CKB input and a fixed 100 CKB destination. The client computes
a fee at the configured fee rate using the final transaction's conservative maximum
witness size. The AccountLock change receives the remainder.

Before prompting for the passkey, the client verifies that both outputs meet occupied
capacity and the AccountLock change remains spendable. It displays the exact fee and
change. It never silently reduces the 100 CKB destination.

## API Surface

The API is intentionally small:

- `GET /api/status`
  - Network, origin policy, verified deployments, funder address, public balance,
    account presence, and browser-safe configuration.
- `GET /api/account`
  - Validated public account manifest, or a typed not-created response.
- `POST /api/account/bootstrap`
  - Validated public passkey registration data; creates the account once or returns the
    matching existing account.

There is no signing, arbitrary transaction, private-key, reset, file-path, or command
execution endpoint.

## Security Model

- Bind only to `127.0.0.1`; never `0.0.0.0` by default.
- Enforce the exact allowed Origin and expected localhost Host.
- Reject browser-supplied network, RPC, origin, RP ID, code hash, capacity, threshold,
  file path, or shell-command overrides.
- Read `CKB_PRIVKEY` only in server-only code and validate it at process startup.
- Never serialize the key, include it in thrown errors, log environment objects, or
  expose it to Vite replacement variables.
- Keep server and client entry graphs separate and scan the production bundle for
  server-only identifiers and secret-handling code.
- Validate all manifests and chain data before using them.
- Refuse a second account bootstrap or mismatched existing account.
- Avoid an automatic reset endpoint because replacing local metadata can strand
  on-chain capacity.
- Label the reference implementation as unaudited and testnet-only at all times.

## Error Handling

All API errors use stable codes, safe user messages, and optional non-sensitive details.
Raw stack traces remain server-side in development and are never returned.

Important states include:

- Unsupported Chromium/WebAuthn capability.
- Local API unavailable or wrong origin.
- Missing, malformed, or insufficiently funded backend key.
- Deployment manifest missing or inconsistent with local artifacts.
- Passkey registration cancelled or public-key extraction unavailable.
- Existing account does not match local credential metadata.
- Bootstrap already in progress or already committed.
- State or asset cell missing, spent, duplicated, or inconsistent.
- Insufficient capacity for destination, change, or fee.
- Passkey assertion cancelled or credential mismatch.
- RPC rejection, transaction rejection, or confirmation timeout.

Passkey cancellation is retryable and not styled as a protocol failure. If submission
returns a transaction hash but confirmation times out, the receipt remains in a
submitted state with its explorer link; the UI does not claim failure or resubmit.

## Persistence

Browser storage contains a versioned record with credential ID and public account
metadata only. The server persists the authoritative public account manifest at
`deploy/testnet-account.json` using an atomic replace.

On startup, the client reconciles browser metadata, server manifest, and live chain
state. A mismatch blocks spending and provides explicit local recovery instructions.
Version one does not attempt credential discovery, cross-device synchronization, or
automatic account recovery.

## Testing

### Rust-generated frontend vectors

Add a host example that emits deterministic fixtures for:

- AccountStateV1 encoding.
- AccountWitnessV1 encoding.
- P256ProofV1 framing inputs and output.
- Canonical group sighash.
- Authorization digest.

Fixtures must carry provenance and remain compatible with the existing ABI-v1 vector
policy. TypeScript tests consume them as immutable expected values.

### TypeScript unit tests

Cover:

- SPKI import and raw 65-byte key validation.
- CKB personalized Blake2b hashing and SHA-256 aux construction.
- Little-endian lengths and overflow rejection.
- P256ProofV1 and AccountWitnessV1 encoding.
- Packed WitnessArgs canonicalization.
- Group sighash and authorization digest against Rust vectors.
- Capacity, occupied-capacity, and conservative fee calculations.
- Deployment, account, and browser-storage schema validation.
- Malformed and over-limit inputs.

### API integration tests

Inject chain-client, signer, filesystem, exporter, and clock dependencies. Test:

- Localhost host/origin enforcement.
- Startup key validation and safe error redaction.
- Deployment verification.
- Bootstrap validation, success, idempotency, mismatch refusal, and atomic persistence.
- Insufficient balance and exporter failure.
- Submission followed by confirmation timeout.
- Absence of arbitrary transaction or command execution behavior.

No default test broadcasts a transaction.

### Chromium browser tests

Use Playwright with a virtual WebAuthn authenticator and mocked API/chain boundaries to
test:

- Unsupported-browser messaging.
- Registration success and cancellation.
- Wizard resume from browser/server state.
- Bootstrap review, pending, success, and failure states.
- Spend review and passkey assertion.
- Submitted-versus-committed receipt behavior.
- Keyboard operation, focus visibility, labels, status semantics, and reduced motion.

### Opt-in testnet smoke test

A separately named command may run the real bootstrap and spend flow only when an
explicit testnet flag and funded `CKB_PRIVKEY` are supplied. It must print capacity use
before broadcasting and retain all explorer hashes on partial failure.

### Build checks

The normal demo check runs formatting, TypeScript type checking, unit and API tests,
Chromium tests, production build, and a bundle scan proving that server-only modules and
private-key handling are absent from client assets.

## Accessibility and Visual Rules

- Use an 8-point spacing scale and a constrained single-column wizard.
- Keep one primary action visible per stage; explorer and diagnostic actions are
  secondary or tertiary.
- Use semantic HTML, associated labels, status regions, and live announcements for
  submission progress.
- Keep every interactive target at least 44 by 44 pixels.
- Preserve visible keyboard focus and meet WCAG AA contrast.
- Communicate all states with text and iconography, never color alone.
- Disable actions during in-flight work without changing their dimensions.
- Respect `prefers-reduced-motion`.
- Show technical hashes in copyable, truncated controls with accessible full values.

## Operational Workflow

The intended local workflow is:

1. Install demo dependencies.
2. Enter `CKB_PRIVKEY` through a hidden shell prompt and export it only for the current
   terminal session.
3. Start the combined localhost client and API development command.
4. Complete the three browser stages.
5. Stop the development processes and unset `CKB_PRIVKEY`.

Documentation must warn that the key funds real testnet transactions and must never be
placed in source files, `.env` files committed to Git, command history, or browser
storage.

## Implementation Boundaries

- Preserve the existing Rust workspace and reproducible contract build behavior.
- Keep browser dependencies outside the Rust workspace.
- Refactor deployment code only where required to share tested bootstrap behavior.
- Do not change ABI v1, contract binaries, deployed code hashes, or existing wire
  formats for frontend convenience.
- If the TypeScript codec disagrees with Rust, fix the TypeScript implementation or the
  design assumption; do not change consensus behavior without a separate protocol
  decision.

