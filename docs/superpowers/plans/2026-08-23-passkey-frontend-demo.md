# Passkey Frontend Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a localhost Chromium demo that creates a P-256 passkey, bootstraps a real CKB testnet AccountLock account, and authorizes a 100 CKB on-chain spend with WebAuthn.

**Architecture:** A React/Vite browser client owns the passkey, builds and signs the custom-lock transaction, and submits it through CCC. A localhost-only Node server holds the one-time funding key and reuses refactored deployment code to bootstrap the account; browser-safe shared modules implement the narrow ABI-v1 codec and validate all manifests against Rust-generated vectors.

**Tech Stack:** Rust 1.97.1, Node.js 22, TypeScript 7, React 19, Vite 8, Vitest 4, Playwright Chromium, Zod 4, and `@ckb-ccc/core` 1.18.2.

**Spec:** `docs/superpowers/specs/2026-08-23-passkey-frontend-demo-design.md`

## Global Constraints

- Target CKB public testnet only.
- Bind the API to `127.0.0.1`; run the client at `http://localhost:5173` and API at `http://127.0.0.1:8787`.
- Use RP ID `localhost`, origin `http://localhost:5173`, ES256 algorithm `-7`, and required user verification.
- Bootstrap exactly one singleton state cell and one 200 CKB AccountLock asset cell.
- Spend exactly 100 CKB back to the backend funder and return remaining capacity, minus fees, to AccountLock.
- Use `data2` for AccountLock scripts and deployed code cells; store verifier hash type `0` (`data`) in AccountStateV1.
- Keep `CKB_PRIVKEY` server-only. Never return, log, persist, interpolate into Vite, or place it in a browser bundle.
- Do not change ABI v1, contract binaries, deployed hashes, or consensus wire formats for frontend convenience.
- Do not add mainnet, non-Chromium, arbitrary-recipient, arbitrary-amount, reset, recovery, rotation, PQ, or general-wallet features.
- Every task follows red-green-refactor: add a focused failing test, observe the expected failure, implement the smallest passing change, run the relevant suite, then commit.
- Preserve the user-owned untracked `deploy/testnet-deployments.json`; never stage it in task commits.

## File Map

### Existing files to modify

- `crates/host/src/lib.rs` — add the host-side P256ProofV1 encoder used as the TypeScript oracle.
- `crates/host/tests/encoding.rs` — pin P256ProofV1 framing and reject malformed inputs.
- `tools/deploy/src/bootstrap.ts` — become a thin CLI around reusable bootstrap functions.
- `tools/deploy/src/bootstrap-lib.ts` — reusable, dependency-injected bootstrap implementation.
- `tools/deploy/test/bootstrap-lib.test.ts` — bootstrap planning, identity, idempotency, and persistence tests.
- `README.md` — link the local demo and state its testnet/unaudited boundary.
- `.gitignore` — ignore demo build output, Playwright output, and local browser state without ignoring deployment manifests.

### New Rust/vector files

- `crates/host/examples/export_frontend_vectors.rs` — deterministic frontend oracle exporter.
- `vectors/frontend-v1.json` — checked-in expected state, proof, witness, sighash, and authorization bytes.
- `vectors/FRONTEND-PROVENANCE.md` — generation command and review boundary.

### New demo foundation and shared files

- `demo/package.json`, `demo/package-lock.json` — isolated Node dependency graph and scripts.
- `demo/tsconfig.json`, `demo/tsconfig.node.json`, `demo/vite.config.ts` — strict client/server compilation and localhost proxy.
- `demo/vitest.config.ts`, `demo/playwright.config.ts` — unit, integration, and Chromium configuration.
- `demo/index.html` — Vite entry document.
- `demo/src/shared/constants.ts` — fixed network, origin, RP, capacity, fee, and protocol values.
- `demo/src/shared/schemas.ts` — Zod schemas and exported API/manifest types.
- `demo/src/shared/bytes.ts` — bounded byte encoding, hashing, base64url, and equality helpers.
- `demo/src/shared/protocol.ts` — P256ProofV1, AccountWitnessV1, group sighash, and authorization digest.
- `demo/src/shared/manifests.ts` — deployment/account manifest loading and cross-checking.

### New server files

- `demo/src/server/config.ts` — startup-only environment parsing and fixed-origin policy.
- `demo/src/server/errors.ts` — typed safe API errors and redaction.
- `demo/src/server/state-exporter.ts` — direct `cargo` child process in a restricted temporary directory.
- `demo/src/server/service.ts` — status, account lookup, and idempotent bootstrap orchestration.
- `demo/src/server/http.ts` — exact three-route localhost HTTP surface.
- `demo/src/server/index.ts` — production dependency wiring and listen call.

### New client files

- `demo/src/client/main.tsx`, `demo/src/client/App.tsx` — React entry and wizard state orchestration.
- `demo/src/client/styles.css` — accessible 8-point design system and responsive single-column layout.
- `demo/src/client/api.ts` — typed calls to the three API routes.
- `demo/src/client/storage.ts` — versioned public credential metadata persistence.
- `demo/src/client/passkey.ts` — WebAuthn registration/assertion and SPKI conversion.
- `demo/src/client/chain.ts` — state/asset discovery, spend preparation/finalization, submission, and confirmation.
- `demo/src/client/components/StatusHeader.tsx` — persistent secondary testnet/API status.
- `demo/src/client/components/PasskeyStep.tsx` — stage-one review and registration action.
- `demo/src/client/components/BootstrapStep.tsx` — stage-two review and bootstrap action.
- `demo/src/client/components/SpendStep.tsx` — stage-three transaction review and assertion action.
- `demo/src/client/components/Receipt.tsx` — submitted/committed receipt and explorer link.

### New tests and operations files

- `demo/test/shared/*.test.ts` — schema, byte, manifest, and protocol unit tests.
- `demo/test/server/*.test.ts` — exporter, service, and HTTP integration tests.
- `demo/test/client/*.test.tsx` — storage, passkey, chain, and component tests.
- `demo/test/browser/demo.spec.ts` — virtual-authenticator wizard coverage.
- `demo/test/browser/real-testnet.spec.ts` — explicitly gated real-chain smoke flow.
- `demo/test/fixtures/frontend-v1.ts` — typed loader for `vectors/frontend-v1.json`.
- `demo/test/fixtures/mock-server.ts` — browser-test API/chain doubles.
- `demo/scripts/check-client-bundle.mjs` — client/server boundary scan.
- `demo/README.md` — hidden-prompt startup, workflow, test commands, recovery, and cleanup.

---

### Task 1: Establish the Rust frontend oracle

**Files:**
- Modify: `crates/host/src/lib.rs`
- Modify: `crates/host/tests/encoding.rs`
- Create: `crates/host/examples/export_frontend_vectors.rs`
- Create: `vectors/frontend-v1.json`
- Create: `vectors/FRONTEND-PROVENANCE.md`

**Interfaces:**
- Produces: `encode_p256_proof(public_key: &[u8], origin: &[u8], authenticator_data: &[u8], client_data_json: &[u8], signature: &[u8]) -> Result<Vec<u8>, ProtocolError>`.
- Produces: JSON fixture fields `state`, `p256_proof`, `account_witness`, `packed_witness_args`, `tx_hash`, `group_sighash`, and `authorization_digest`, each encoded as `0x` hex.
- Consumes: existing `encode_state`, `encode_witness`, `group_sighash`, `authorization_digest`, and ABI-v1 constants.

- [ ] **Step 1: Add failing host tests for exact P256ProofV1 framing**

Append tests that construct a 65-byte uncompressed public key, origin, 37-byte authenticator data, flat `clientDataJSON`, and DER signature. Assert exact field order and little-endian lengths, and assert rejection for public keys not exactly 65 bytes, empty origin, authenticator data shorter than 37 bytes, empty client data, and empty signature.

```rust
#[test]
fn p256_proof_encoder_matches_abi_v1_layout() {
    let mut key = [0x11; 65];
    key[0] = 0x04;
    let proof = encode_p256_proof(
        &key,
        b"http://localhost:5173",
        &[0x22; 37],
        br#"{"type":"webauthn.get","challenge":"AA","origin":"http://localhost:5173"}"#,
        &[0x30, 0x02, 0x01, 0x01],
    )
    .unwrap();
    assert_eq!(&proof[..65], &key);
    assert_eq!(proof[65], 21);
    assert_eq!(u16::from_le_bytes([proof[87], proof[88]]), 37);
}
```

- [ ] **Step 2: Run the focused Rust test and observe the missing symbol**

Run: `cargo test -p ckb-account-host --test encoding p256_proof_encoder -- --nocapture`

Expected: compile failure because `encode_p256_proof` is not defined.

- [ ] **Step 3: Implement the bounded host encoder**

Add a public encoder that mirrors `contracts/verifier-p256/src/main.rs::parse_proof`, uses `u16_len`, and returns `ProtocolError::InvalidProof` for the constraints above.

```rust
pub fn encode_p256_proof(
    public_key: &[u8],
    origin: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if public_key.len() != 65
        || public_key[0] != 0x04
        || origin.is_empty()
        || origin.len() > u8::MAX as usize
        || authenticator_data.len() < 37
        || client_data_json.is_empty()
        || signature.is_empty()
    {
        return Err(ProtocolError::InvalidProof);
    }
    let mut out = Vec::new();
    out.extend_from_slice(public_key);
    out.push(origin.len() as u8);
    out.extend_from_slice(origin);
    out.extend_from_slice(&u16_len(authenticator_data.len())?.to_le_bytes());
    out.extend_from_slice(authenticator_data);
    out.extend_from_slice(&u16_len(client_data_json.len())?.to_le_bytes());
    out.extend_from_slice(client_data_json);
    out.extend_from_slice(&u16_len(signature.len())?.to_le_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}
```

- [ ] **Step 4: Run the host tests**

Run: `cargo test -p ckb-account-host --test encoding`

Expected: all encoding tests pass.

- [ ] **Step 5: Add the deterministic vector exporter and provenance**

Use fixed byte arrays, a packed `WitnessArgs`, and a fixed `H256` transaction hash. Serialize one JSON object with schema version 1 and lowercase `0x` hex values. Document the exact regeneration command:

```bash
cargo run -p ckb-account-host --example export_frontend_vectors -- vectors/frontend-v1.json
```

The exporter must write only its explicit output path and must immediately parse or recompute every generated value before writing.

- [ ] **Step 6: Regenerate and verify the vector**

Run: `cargo run -p ckb-account-host --example export_frontend_vectors -- vectors/frontend-v1.json`

Run: `cargo test -p ckb-account-host`

Run: `git diff --check`

Expected: deterministic vector exists; all host tests pass; no whitespace errors.

- [ ] **Step 7: Commit the Rust oracle**

```bash
git add crates/host/src/lib.rs crates/host/tests/encoding.rs crates/host/examples/export_frontend_vectors.rs vectors/frontend-v1.json vectors/FRONTEND-PROVENANCE.md
git commit -m "Add frontend protocol vectors"
```

### Task 2: Scaffold the isolated demo and public schemas

**Files:**
- Create: `demo/package.json`
- Create: `demo/package-lock.json`
- Create: `demo/tsconfig.json`
- Create: `demo/tsconfig.node.json`
- Create: `demo/vite.config.ts`
- Create: `demo/vitest.config.ts`
- Create: `demo/playwright.config.ts`
- Create: `demo/index.html`
- Create: `demo/src/shared/constants.ts`
- Create: `demo/src/shared/schemas.ts`
- Create: `demo/test/shared/schemas.test.ts`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `DeploymentManifest`, `AccountManifest`, `PasskeyRecord`, `DemoStatus`, `BootstrapRequest`, `ApiErrorBody`, `SubmittedReceipt`, `CommittedReceipt`, and `ConfirmationTimedOutReceipt` inferred from Zod schemas; `TransactionReceipt` is their discriminated union.
- Produces: fixed constants `CLIENT_ORIGIN`, `RP_ID`, `API_ORIGIN`, `INITIAL_ASSET`, `TRANSFER_CAPACITY`, `FEE_RATE`, `OP_SPEND`, and `EXPLORER_URL`.
- Consumes: Node 22 and `@ckb-ccc/core` 1.18.2.

- [ ] **Step 1: Create the package scripts and strict configs**

Use these scripts as the stable operational interface:

```json
{
  "scripts": {
    "dev": "concurrently -k -n api,web \"npm:dev:server\" \"npm:dev:client\"",
    "dev:server": "tsx watch src/server/index.ts",
    "dev:client": "vite --host 127.0.0.1 --port 5173 --strictPort",
    "test": "vitest run",
    "test:browser": "playwright test test/browser/demo.spec.ts",
    "test:testnet": "playwright test test/browser/real-testnet.spec.ts",
    "typecheck": "tsc --noEmit && tsc -p tsconfig.node.json --noEmit",
    "build": "vite build",
    "check:bundle": "node scripts/check-client-bundle.mjs",
    "check": "npm run typecheck && npm test && npm run test:browser && npm run build && npm run check:bundle"
  }
}
```

Add runtime dependencies for CCC, React, React DOM, and Zod; add development dependencies for TypeScript, TSX, Vite, the React plugin, Vitest, jsdom, Testing Library, Playwright, and concurrently. Pin CCC to `1.18.2` to match deployment tooling.

Configure Vite's `/api` proxy with target `http://127.0.0.1:8787` and `changeOrigin: true`. The backend therefore requires `Host: 127.0.0.1:8787` and the forwarded browser `Origin: http://localhost:5173`.

- [ ] **Step 2: Write schema tests before schemas**

Assert that deployment manifests accept the two published records and reject mainnet, non-`data2`, missing outpoints, and non-32-byte hashes. Assert that account manifests accept schema version 1 and reject wrong AccountLock args length. Assert that bootstrap requests reject caller-supplied network, origin, RP ID, amount, or file-path fields because the strict object schema must reject unknown keys.

```ts
expect(() => BootstrapRequestSchema.parse({ publicKey, credentialId })).not.toThrow();
expect(() => BootstrapRequestSchema.parse({ publicKey, credentialId, network: "mainnet" })).toThrow();
```

- [ ] **Step 3: Run the schema test and observe missing modules**

Run: `npm --prefix demo test -- schemas.test.ts`

Expected: failure because `src/shared/schemas.ts` does not exist.

- [ ] **Step 4: Implement fixed constants and strict schemas**

Define all hex schemas with exact byte counts. Keep API errors stable:

```ts
export const ApiErrorBodySchema = z.object({
  error: z.object({
    code: z.enum([
      "BAD_ORIGIN", "INVALID_REQUEST", "KEY_UNAVAILABLE", "DEPLOYMENT_INVALID",
      "ACCOUNT_NOT_CREATED", "ACCOUNT_MISMATCH", "INSUFFICIENT_BALANCE",
      "BOOTSTRAP_FAILED", "CONFIRMATION_TIMEOUT", "INTERNAL_ERROR",
    ]),
    message: z.string().max(240),
  }).strict(),
}).strict();
```

Use BigInt-safe decimal strings in JSON for all capacities.

- [ ] **Step 5: Install, lock, and verify the scaffold**

Run: `npm --prefix demo install`

Run: `npm --prefix demo test -- schemas.test.ts`

Run: `npm --prefix demo run typecheck`

Expected: schema tests and both client/server type checks pass.

- [ ] **Step 6: Commit the demo foundation**

```bash
git add .gitignore demo/package.json demo/package-lock.json demo/tsconfig.json demo/tsconfig.node.json demo/vite.config.ts demo/vitest.config.ts demo/playwright.config.ts demo/index.html demo/src/shared/constants.ts demo/src/shared/schemas.ts demo/test/shared/schemas.test.ts
git commit -m "Scaffold passkey demo"
```

### Task 3: Implement the browser-safe ABI-v1 codec

**Files:**
- Create: `demo/src/shared/bytes.ts`
- Create: `demo/src/shared/protocol.ts`
- Create: `demo/test/fixtures/frontend-v1.ts`
- Create: `demo/test/shared/bytes.test.ts`
- Create: `demo/test/shared/protocol.test.ts`

**Interfaces:**
- Produces: `ckbHash(data: Uint8Array): Uint8Array`.
- Produces: `encodeP256Proof(input: P256ProofInput): Uint8Array`.
- Produces: `encodeAccountWitness(operation: 1, sequence: bigint, proofs: readonly Proof[]): Uint8Array`.
- Produces: `groupSighash(txHash: Uint8Array, groupWitnesses: readonly Uint8Array[], extraWitnesses: readonly Uint8Array[]): Uint8Array`.
- Produces: `authorizationDigest(input: AuthorizationInput): Uint8Array`.
- Consumes: `vectors/frontend-v1.json` and CCC's Molecule `WitnessArgs` codec.

- [ ] **Step 1: Write vector-backed failing tests**

Load the checked-in Rust fixture outside Vite's client graph. Assert exact hex equality for P256ProofV1, AccountWitnessV1, packed WitnessArgs, group sighash, authorization digest, and CKB hash. Add negative tests for unsorted/duplicate proof slots, oversized lengths, invalid operation, wrong hash size, non-65-byte key, and malformed WitnessArgs.

```ts
expect(hexFrom(encodeP256Proof(vector.inputs.p256))).toBe(vector.p256_proof);
expect(hexFrom(groupSighash(txHash, [witness], []))).toBe(vector.group_sighash);
```

- [ ] **Step 2: Run the protocol tests and observe missing functions**

Run: `npm --prefix demo test -- protocol.test.ts bytes.test.ts`

Expected: module-not-found failures for `bytes.ts` and `protocol.ts`.

- [ ] **Step 3: Implement bounded byte helpers**

Implement explicit little-endian writers that throw before truncation:

```ts
export function u16le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError("u16");
  return Uint8Array.of(value & 0xff, value >>> 8);
}

export function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new RangeError("u64");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}
```

Use `ccc.hashCkb` for the personalized CKB hash; do not substitute WebCrypto Blake2b.

- [ ] **Step 4: Implement the exact protocol encoders and hashes**

For group sighash, parse the first packed witness, replace `lock` with present empty bytes (`0x`), serialize it, and hash transaction hash plus `u64le(length) || witness` for the canonical first witness, remaining group witnesses, and extra witnesses. For authorization, concatenate exactly `AUTH_DOMAIN`, operation byte, account ID, sequence, state hash, and group sighash.

- [ ] **Step 5: Verify TypeScript against Rust**

Run: `npm --prefix demo test -- protocol.test.ts bytes.test.ts`

Run: `cargo run -p ckb-account-host --example export_frontend_vectors -- /tmp/frontend-v1.json`

Run: `cmp vectors/frontend-v1.json /tmp/frontend-v1.json`

Expected: all TypeScript tests pass and the regenerated Rust vector is identical.

- [ ] **Step 6: Commit the codec**

```bash
git add demo/src/shared/bytes.ts demo/src/shared/protocol.ts demo/test/fixtures/frontend-v1.ts demo/test/shared/bytes.test.ts demo/test/shared/protocol.test.ts
git commit -m "Implement browser ABI v1 codec"
```

### Task 4: Refactor bootstrap into a reusable deployment service

**Files:**
- Create: `tools/deploy/src/bootstrap-lib.ts`
- Modify: `tools/deploy/src/bootstrap.ts`
- Create: `tools/deploy/test/bootstrap-lib.test.ts`

**Interfaces:**
- Produces: `BootstrapOptions { stateData: Uint8Array; assetCapacityCkb: bigint }`.
- Produces: `BootstrapDeps { repoRoot: string; client: ccc.Client; signer: ccc.Signer; readJson(path): unknown; writeJsonAtomic(path, value): void }`.
- Produces: `TestnetAccountManifest` in `bootstrap-lib.ts`, structurally compatible with the demo's separately validated `AccountManifest` schema.
- Produces: `bootstrapAccount(options: BootstrapOptions, deps: BootstrapDeps): Promise<TestnetAccountManifest>`.
- Preserves: existing `npm run bootstrap -- --state ... [--broadcast]` behavior.

- [ ] **Step 1: Write failing library tests around existing invariants**

Use fake CCC client/signer boundaries and fixed inputs. Cover: state bytes required, 200 CKB default, occupied-capacity rejection, `data2` AccountLock, Type ID patching from first input, identical lock args on state and asset outputs, trailing funder change, commitment wait, and returned manifest fields. Assert no write occurs before commitment.

- [ ] **Step 2: Run the focused deploy test**

Run: `npm --prefix tools/deploy test -- bootstrap-lib.test.ts`

Expected: failure because `bootstrap-lib.ts` is absent.

- [ ] **Step 3: Extract transaction creation without changing behavior**

Move plan/build/broadcast logic from `bootstrap.ts` into the exported function. Keep CLI-only parsing and console output in `bootstrap.ts`. Inject filesystem persistence and chain boundaries so tests cannot touch the network.

```ts
export async function bootstrapAccount(
  options: BootstrapOptions,
  deps: BootstrapDeps,
): Promise<TestnetAccountManifest> {
  const tx = buildBootstrapTransaction(options, deps);
  await tx.completeInputsByCapacity(deps.signer);
  patchAccountIdentity(tx);
  await tx.completeFeeBy(deps.signer, FEE_RATE);
  assertCreationConsistency(tx, accountLockHash, ccc.hexFrom(options.stateData));
  const txHash = await deps.signer.sendTransaction(tx);
  await deps.client.waitTransaction(txHash, 0, 300_000);
  const manifest = manifestFromCommittedTransaction(tx, txHash, options.stateData.length);
  deps.writeJsonAtomic(accountPath, manifest);
  return manifest;
}
```

- [ ] **Step 4: Make CLI persistence atomic**

Write JSON to a sibling temporary file opened with mode `0o600`, fsync/close it, then rename it over `deploy/testnet-account.json`. Never overwrite an existing mismatched account manifest.

- [ ] **Step 5: Run deploy and dry-run regression checks**

Run: `npm --prefix tools/deploy test`

Run: `npm --prefix tools/deploy run typecheck`

Run: `npm --prefix tools/deploy run bootstrap -- --state /dev/null`

Expected: tests/typecheck pass; dry run rejects empty state without network access.

- [ ] **Step 6: Commit the reusable bootstrap service**

```bash
git add tools/deploy/src/bootstrap.ts tools/deploy/src/bootstrap-lib.ts tools/deploy/test/bootstrap-lib.test.ts
git commit -m "Refactor reusable account bootstrap"
```

### Task 5: Implement secure state export and server configuration

**Files:**
- Create: `demo/src/server/config.ts`
- Create: `demo/src/server/errors.ts`
- Create: `demo/src/server/state-exporter.ts`
- Create: `demo/test/server/config.test.ts`
- Create: `demo/test/server/state-exporter.test.ts`

**Interfaces:**
- Produces: `loadServerConfig(env: NodeJS.ProcessEnv): ServerConfig` with validated private key held only in the returned server object.
- Produces: `exportAccountState(request: BootstrapRequest, deps: ExporterDeps): Promise<Uint8Array>`.
- Produces: `ApiError(code, status, safeMessage)` and `toSafeErrorBody(error)`.
- Consumes: fixed deployment hash from the deployment manifest; it never accepts code hashes from the browser.

- [ ] **Step 1: Write failing startup and exporter tests**

Assert exact `0x` + 64-hex private-key validation, fixed host/origin values, and safe redaction. For exporter tests, inject `spawnProcess`, `makeTempDir`, and filesystem functions; assert argv is a direct cargo argument array, configuration fields are recomputed server-side, output is non-empty, and cleanup runs on success and failure.

- [ ] **Step 2: Run the focused server tests**

Run: `npm --prefix demo test -- config.test.ts state-exporter.test.ts`

Expected: missing-module failures.

- [ ] **Step 3: Implement startup validation and safe errors**

Do not include the key in error interpolation:

```ts
if (!/^0x[0-9a-fA-F]{64}$/.test(env.CKB_PRIVKEY ?? "")) {
  throw new ApiError("KEY_UNAVAILABLE", 500, "CKB_PRIVKEY is missing or invalid");
}
```

Keep the key property non-enumerable or in a closure-owned dependency so accidental JSON serialization cannot expose it.

- [ ] **Step 4: Implement direct Rust exporter execution**

Create a restricted directory with `mkdtemp`, write the JSON config with mode `0o600`, invoke `cargo` with `shell: false` and exact argv, read the binary output, reject zero length, and recursively remove only the resolved temporary directory in `finally`.

- [ ] **Step 5: Run tests and typecheck**

Run: `npm --prefix demo test -- config.test.ts state-exporter.test.ts`

Run: `npm --prefix demo run typecheck`

Expected: all focused tests and type checks pass.

- [ ] **Step 6: Commit secure server primitives**

```bash
git add demo/src/server/config.ts demo/src/server/errors.ts demo/src/server/state-exporter.ts demo/test/server/config.test.ts demo/test/server/state-exporter.test.ts
git commit -m "Add secure demo server primitives"
```

### Task 6: Expose the three-route localhost API

**Files:**
- Create: `demo/src/server/service.ts`
- Create: `demo/src/server/http.ts`
- Create: `demo/src/server/index.ts`
- Create: `demo/test/server/service.test.ts`
- Create: `demo/test/server/http.test.ts`

**Interfaces:**
- Produces: `DemoService.status(): Promise<DemoStatus>`.
- Produces: `DemoService.account(): Promise<AccountManifest | null>`.
- Produces: `DemoService.bootstrap(request: BootstrapRequest): Promise<AccountManifest>`.
- Produces: `createHttpServer(service: DemoService): http.Server` with only `GET /api/status`, `GET /api/account`, and `POST /api/account/bootstrap`.
- Consumes: Task 4 bootstrap library and Task 5 state exporter/config/error functions.

- [ ] **Step 1: Write failing service tests**

Cover deployment hash/outpoint validation, public funder address/balance, account absence, matching account idempotency, mismatched key refusal, concurrent bootstrap serialization, insufficient balance, exporter failure, commitment timeout, and atomic manifest visibility.

- [ ] **Step 2: Write failing HTTP boundary tests**

Start the server on an ephemeral `127.0.0.1` port. Assert exact origin/host enforcement, JSON content type, 16 KiB body limit, strict request schema, `405` for wrong methods, `404` for unknown paths, no CORS wildcard, no stack/key leakage, and absence of sign/reset/path/command routes.

- [ ] **Step 3: Run service and HTTP tests**

Run: `npm --prefix demo test -- service.test.ts http.test.ts`

Expected: missing service/server failures.

- [ ] **Step 4: Implement idempotent orchestration**

Guard bootstrap with one in-process promise. Export the request's expected state bytes before checking an existing manifest. If a manifest exists, fetch its state outpoint through the injected client and compare the complete on-chain state data with those expected bytes; return the manifest only on exact equality, otherwise raise `ACCOUNT_MISMATCH`. Check the funder can cover state occupied capacity + 200 CKB + fees before broadcasting.

- [ ] **Step 5: Implement the exact HTTP surface**

Use Node's native HTTP server. Reject before reading bodies when host/origin is wrong. Set `Access-Control-Allow-Origin` only to `http://localhost:5173`, `Vary: Origin`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and a restrictive CSP on JSON responses.

- [ ] **Step 6: Wire production dependencies**

In `index.ts`, load config once, construct `ClientPublicTestnet` and `SignerCkbPrivateKey`, create the exporter and bootstrap dependencies, then listen only on `127.0.0.1:8787`. Log address, network, and public balance; never log config or environment objects.

- [ ] **Step 7: Run all server tests**

Run: `npm --prefix demo test -- test/server`

Run: `npm --prefix demo run typecheck`

Expected: all server tests and type checks pass.

- [ ] **Step 8: Commit the localhost API**

```bash
git add demo/src/server/service.ts demo/src/server/http.ts demo/src/server/index.ts demo/test/server/service.test.ts demo/test/server/http.test.ts
git commit -m "Add localhost bootstrap API"
```

### Task 7: Implement passkey registration, assertion, and storage

**Files:**
- Create: `demo/src/client/storage.ts`
- Create: `demo/src/client/passkey.ts`
- Create: `demo/test/client/storage.test.ts`
- Create: `demo/test/client/passkey.test.ts`

**Interfaces:**
- Produces: `loadPasskeyRecord(storage: Storage): PasskeyRecord | null` and `savePasskeyRecord(storage, record): void`.
- Produces: `registerPasskey(credentials: CredentialsContainer, crypto: Crypto): Promise<PasskeyRecord>`.
- Produces: `requestAssertion(challenge: Uint8Array, record: PasskeyRecord, credentials: CredentialsContainer): Promise<AssertionMaterial>`.
- Consumes: fixed origin/RP constants, `ckbHash`, base64url helpers, and schemas.

- [ ] **Step 1: Write failing storage tests**

Cover schema-version round trip, malformed JSON, wrong origin/RP, non-public fields, and incompatible schema removal from active state. Do not add a UI reset function.

- [ ] **Step 2: Write failing passkey tests with injected credentials**

Use a known P-256 SPKI fixture. Assert registration options include ES256, `localhost`, resident-key preference, and required user verification. Assert SPKI import/export yields 65 bytes beginning `0x04`, key ID uses CKB hash, aux uses SHA-256 of fixed RP/origin, and assertion passes the exact 32-byte challenge with one allowed credential.

- [ ] **Step 3: Run client primitive tests**

Run: `npm --prefix demo test -- storage.test.ts passkey.test.ts`

Expected: missing module failures.

- [ ] **Step 4: Implement versioned public storage**

Store only schema version, credential ID, public key, key ID, RP ID, origin, and created timestamp. Reject any record containing a `privateKey`, `CKB_PRIVKEY`, or unknown property through the strict schema.

- [ ] **Step 5: Implement registration and assertion**

Require `PublicKeyCredential`, `isSecureContext`, `AuthenticatorAttestationResponse.getPublicKey`, and non-null credential responses. Import SPKI with WebCrypto ECDSA/P-256 and export `raw`. Treat `NotAllowedError` as `PasskeyCancelledError`; treat all malformed responses as non-retryable protocol errors.

- [ ] **Step 6: Verify the passkey module**

Run: `npm --prefix demo test -- storage.test.ts passkey.test.ts`

Run: `npm --prefix demo run typecheck`

Expected: all client primitive tests and type checks pass.

- [ ] **Step 7: Commit passkey primitives**

```bash
git add demo/src/client/storage.ts demo/src/client/passkey.ts demo/test/client/storage.test.ts demo/test/client/passkey.test.ts
git commit -m "Add browser passkey primitives"
```

### Task 8: Build, finalize, and submit the AccountLock spend

**Files:**
- Create: `demo/src/shared/manifests.ts`
- Create: `demo/src/client/chain.ts`
- Create: `demo/test/shared/manifests.test.ts`
- Create: `demo/test/client/chain.test.ts`

**Interfaces:**
- Produces: `validateDeployment(manifest): VerifiedDeployment` and `validateAccount(manifest, deployment): VerifiedAccount`.
- Produces: `discoverAccountCells(client, account): Promise<{ state: ccc.Cell; asset: ccc.Cell }>`.
- Produces: `prepareSpend(input: PrepareSpendInput): Promise<PreparedSpend>` where the result contains `transaction`, `authorizationDigest`, `review`, and `maxWitnessBytes`.
- Produces: `finalizeSpend(prepared, passkey, assertion): ccc.Transaction`.
- Produces: `submitSpend(client, tx): Promise<SubmittedReceipt>`; this function only submits and returns `{ status: "submitted", txHash }`.
- Produces: `confirmSpend(client, submitted): Promise<CommittedReceipt | ConfirmationTimedOutReceipt>`; this function never submits or resubmits.
- Consumes: Tasks 2, 3, and 7 types and codec functions.

- [ ] **Step 1: Write failing manifest and discovery tests**

Validate code hashes against recorded data hashes, outpoint indexes, AccountLock args `0x01 || account_id`, Type ID script hash, exact state outpoint, and chain data. Discovery must reject zero assets, multiple untyped assets, a typed asset candidate, foreign lock args, or spent state.

- [ ] **Step 2: Write failing spend construction tests**

With a fake CCC client and fixed cells, assert one input, two outputs, exact 100 CKB funder output, AccountLock change, and exactly three `code` deps in deterministic order: AccountLock, P-256 verifier, state. Assert no secp dep is added because the funder lock appears only on an output. Assert both outputs satisfy occupied capacity.

- [ ] **Step 3: Write failing digest/finalization tests**

Build a maximum-size placeholder witness before estimating fees. After fee/change are fixed, compute the raw tx hash, canonical group sighash, and authorization digest. Replace the placeholder with a real assertion whose encoded size is at or below the reservation, and assert the raw transaction hash/digest are unchanged.

- [ ] **Step 4: Run chain tests**

Run: `npm --prefix demo test -- manifests.test.ts chain.test.ts`

Expected: missing implementation failures.

- [ ] **Step 5: Implement verified discovery and fixed transaction building**

Use `client.findCellsByLock(accountLock, undefined, true, "asc", 3)` and require exactly one type-less asset. Fetch the state cell by outpoint and compare its data and scripts before constructing anything. Parse the funder address with `await ccc.Address.fromString(status.funderAddress, client)`.

- [ ] **Step 6: Reserve witness size and calculate a conservative fee**

Construct a syntactically valid maximum proof using 65-byte key, fixed origin, 1024-byte authenticator data, 2048-byte client data, and 72-byte DER reservation. Encode it into AccountWitnessV1 and packed WitnessArgs, set it on the transaction, call `tx.estimateFee(FEE_RATE)`, and set change to `input - 100 CKB - fee`. Do not recalculate outputs after the WebAuthn assertion.

- [ ] **Step 7: Implement finalization and submission states**

Validate returned credential ID and all proof component bounds, encode the real witness, require its byte size not to exceed `maxWitnessBytes`, and set it. Implement `submitSpend` as the single call to `client.sendTransaction(tx)`. Implement `confirmSpend` as the separate `client.waitTransaction(txHash, 0, 300_000)` and rescan path; on timeout it returns the original hash with status `confirmation-timeout` and never calls `sendTransaction`.

- [ ] **Step 8: Verify chain logic**

Run: `npm --prefix demo test -- manifests.test.ts chain.test.ts`

Run: `npm --prefix demo run typecheck`

Expected: all chain tests and type checks pass.

- [ ] **Step 9: Commit browser transaction logic**

```bash
git add demo/src/shared/manifests.ts demo/src/client/chain.ts demo/test/shared/manifests.test.ts demo/test/client/chain.test.ts
git commit -m "Build browser AccountLock spends"
```

### Task 9: Build the API client and wizard shell

**Files:**
- Create: `demo/src/client/api.ts`
- Create: `demo/src/client/main.tsx`
- Create: `demo/src/client/App.tsx`
- Create: `demo/src/client/components/StatusHeader.tsx`
- Create: `demo/src/client/styles.css`
- Create: `demo/test/client/App.test.tsx`

**Interfaces:**
- Produces: `DemoApi` methods `status()`, `account()`, and `bootstrap(request)` validated through shared schemas.
- Produces: wizard states `loading | needs-passkey | needs-account | ready-to-spend | submitted | committed | blocked`.
- Consumes: Tasks 2 and 7 public schemas/storage.

- [ ] **Step 1: Write failing shell tests**

Render with injected API/storage. Assert loading state, unsupported-browser block, current step selection from reconciled browser/server state, persistent testnet/localhost/unaudited labels, status address/balance, and exactly one enabled primary action per stage.

- [ ] **Step 2: Run the shell test**

Run: `npm --prefix demo test -- App.test.tsx`

Expected: missing React entry/components.

- [ ] **Step 3: Implement schema-validating API calls**

Use relative `/api` URLs through the Vite proxy, `credentials: "omit"`, `cache: "no-store"`, exact JSON content type, and shared response schemas. Convert `ApiErrorBody` into typed client errors without displaying raw response bodies.

- [ ] **Step 4: Implement wizard reconciliation**

On load, fetch status/account and load browser storage. Block on credential/account mismatch. Never infer success only from local storage. Keep every in-flight state explicit so buttons cannot double-submit.

- [ ] **Step 5: Implement the visual foundation**

Use a 720px maximum single column, 8-point spacing scale, system UI font, 44px targets, two font weights, visible 2px focus rings, semantic status elements, and `prefers-reduced-motion`. Use one filled primary button per active card; explorer/hash controls remain secondary.

- [ ] **Step 6: Verify shell and accessibility basics**

Run: `npm --prefix demo test -- App.test.tsx`

Run: `npm --prefix demo run typecheck`

Expected: shell tests and type checks pass.

- [ ] **Step 7: Commit the wizard shell**

```bash
git add demo/src/client/api.ts demo/src/client/main.tsx demo/src/client/App.tsx demo/src/client/components/StatusHeader.tsx demo/src/client/styles.css demo/test/client/App.test.tsx
git commit -m "Add passkey demo wizard shell"
```

### Task 10: Connect passkey registration and account bootstrap stages

**Files:**
- Create: `demo/src/client/components/PasskeyStep.tsx`
- Create: `demo/src/client/components/BootstrapStep.tsx`
- Modify: `demo/src/client/App.tsx`
- Create: `demo/test/client/PasskeyStep.test.tsx`
- Create: `demo/test/client/BootstrapStep.test.tsx`

**Interfaces:**
- Produces: `PasskeyStep` callback `onCreated(record: PasskeyRecord): void`.
- Produces: `BootstrapStep` callback `onCreated(account: AccountManifest): void`.
- Consumes: `registerPasskey`, `savePasskeyRecord`, and `DemoApi.bootstrap`.

- [ ] **Step 1: Write failing registration-stage tests**

Assert review copy, unsupported capability explanation, disabled/loading state with stable dimensions, cancellation returning to ready state, successful public key/key ID display, storage write, and live-region announcement.

- [ ] **Step 2: Write failing bootstrap-stage tests**

Assert 200 CKB/funder/code-hash review, one primary action, duplicate-click prevention, matching idempotent response, mismatch block, explorer link, and inline safe errors for insufficient balance/export/broadcast timeout.

- [ ] **Step 3: Run stage tests**

Run: `npm --prefix demo test -- PasskeyStep.test.tsx BootstrapStep.test.tsx`

Expected: missing component failures.

- [ ] **Step 4: Implement passkey stage**

Inject the registration function for tests. Treat `PasskeyCancelledError` as retryable copy (“Passkey creation was cancelled”) and every malformed response as a blocking compatibility error. Persist only after all derived fields validate.

- [ ] **Step 5: Implement bootstrap stage**

Send only credential ID and public key. The server recomputes key ID/aux. Show submitted and committed progress without inventing a transaction hash before the API returns one. Re-fetch status/account after success.

- [ ] **Step 6: Verify both stages**

Run: `npm --prefix demo test -- PasskeyStep.test.tsx BootstrapStep.test.tsx App.test.tsx`

Expected: all stage and shell tests pass.

- [ ] **Step 7: Commit registration and bootstrap UI**

```bash
git add demo/src/client/components/PasskeyStep.tsx demo/src/client/components/BootstrapStep.tsx demo/src/client/App.tsx demo/test/client/PasskeyStep.test.tsx demo/test/client/BootstrapStep.test.tsx
git commit -m "Connect passkey account setup flow"
```

### Task 11: Connect spend review, assertion, and receipt

**Files:**
- Create: `demo/src/client/components/SpendStep.tsx`
- Create: `demo/src/client/components/Receipt.tsx`
- Modify: `demo/src/client/App.tsx`
- Create: `demo/test/client/SpendStep.test.tsx`
- Create: `demo/test/client/Receipt.test.tsx`

**Interfaces:**
- Produces: `SpendStep` orchestration from `prepareSpend` through `requestAssertion`, `finalizeSpend`, `submitSpend`, and `confirmSpend`.
- Produces: `Receipt` for submitted, committed, and confirmation-timeout states.
- Consumes: verified account/passkey/status data and Task 8 chain functions.

- [ ] **Step 1: Write failing spend review tests**

Assert visible input capacity, exact 100 CKB destination, change, fee, three dependency identities, no action before successful discovery, passkey cancellation retry, credential mismatch block, and no output mutation after challenge creation.

- [ ] **Step 2: Write failing receipt tests**

Assert transaction hash appears immediately after submission, explorer URL uses testnet, committed state is distinct, timeout preserves submitted state and does not resubmit, hashes are copyable with accessible full values, and remaining AccountLock capacity appears only after a successful rescan.

- [ ] **Step 3: Run spend/receipt tests**

Run: `npm --prefix demo test -- SpendStep.test.tsx Receipt.test.tsx`

Expected: missing component failures.

- [ ] **Step 4: Implement spend orchestration**

Prepare and render the transaction before enabling authorization. On click, freeze the prepared transaction object, request the assertion using its digest, finalize only the witness, submit, store the receipt, then wait/rescan. Disable the primary action for all in-flight states.

- [ ] **Step 5: Implement resilient receipt behavior**

Use a persistent submitted receipt for RPC timeouts. Provide a tertiary **Check again** action that queries the existing hash and never broadcasts. Use a semantic `<output>`/status region for state changes and a normal anchor with `rel="noreferrer"` for explorer navigation.

- [ ] **Step 6: Verify the complete component flow**

Run: `npm --prefix demo test -- test/client`

Run: `npm --prefix demo run typecheck`

Expected: all client tests and type checks pass.

- [ ] **Step 7: Commit spend UI**

```bash
git add demo/src/client/components/SpendStep.tsx demo/src/client/components/Receipt.tsx demo/src/client/App.tsx demo/test/client/SpendStep.test.tsx demo/test/client/Receipt.test.tsx
git commit -m "Complete passkey spend experience"
```

### Task 12: Add Chromium coverage, bundle isolation, and operator documentation

**Files:**
- Create: `demo/test/fixtures/mock-server.ts`
- Create: `demo/test/browser/demo.spec.ts`
- Create: `demo/test/browser/real-testnet.spec.ts`
- Create: `demo/scripts/check-client-bundle.mjs`
- Create: `demo/README.md`
- Modify: `README.md`

**Interfaces:**
- Produces: `npm run check` as the default no-broadcast verification command.
- Produces: `RUN_CKB_TESTNET=1 npm run test:testnet` as the only automated real-chain entry.
- Consumes: all previous tasks.

- [ ] **Step 1: Write the browser test against a virtual authenticator**

Use Playwright's Chromium CDP session to enable WebAuthn and add a CTAP2 virtual authenticator with resident keys and user verification. Exercise registration, bootstrap, transaction review, assertion, submitted receipt, committed receipt, cancellation retry, refresh/resume, keyboard tab order, and reduced-motion mode against deterministic mock API/chain fixtures.

- [ ] **Step 2: Run the browser test and observe missing harness pieces**

Run: `npm --prefix demo run test:browser`

Expected: failure until mock server and final selectors are wired.

- [ ] **Step 3: Implement deterministic browser fixtures**

The fixture server must return fixed public manifests/cells and verify incoming requests; it must never import `src/server/index.ts`, read environment secrets, or broadcast. Give controls for cancellation, confirmation timeout, and committed rescan.

- [ ] **Step 4: Add the explicit real-testnet gate**

At the first line of `real-testnet.spec.ts`, skip unless both `RUN_CKB_TESTNET === "1"` and `CKB_PRIVKEY` matches the private-key format. Print the planned capacity use before calling bootstrap. Use a virtual authenticator, retain account/transaction hashes on every partial failure, and run serially with one worker.

- [ ] **Step 5: Add the client bundle boundary scan**

Recursively scan `demo/dist` text assets and fail if they contain `CKB_PRIVKEY`, `SignerCkbPrivateKey`, `bootstrap-lib`, `child_process`, `state-exporter`, or `src/server`. Also inspect Vite's manifest/module graph when available to ensure server sources are absent rather than relying only on string minification.

- [ ] **Step 6: Write operator documentation**

Document prerequisites, `npm install`, hidden-prompt key entry, `npm run dev`, the three stages, explorer verification, `unset CKB_PRIVKEY`, account-manifest mismatch recovery, and all verification commands. Use this startup block:

```bash
cd demo
read -rsp "CKB testnet private key (0x…): " CKB_PRIVKEY
echo
export CKB_PRIVKEY
npm run dev
# After stopping the demo:
unset CKB_PRIVKEY
```

Warn not to paste keys into chat, command arguments, `.env`, browser storage, or committed files.

- [ ] **Step 7: Run the complete no-broadcast verification suite**

Run: `cargo test -p ckb-account-host`

Run: `npm --prefix tools/deploy test`

Run: `npm --prefix tools/deploy run typecheck`

Run: `npx playwright install chromium` from `demo/` if Chromium is not installed.

Run: `npm --prefix demo run check`

Run: `./scripts/check.sh`

Run: `git diff --check`

Expected: all Rust, deploy, unit, integration, browser, build, bundle-boundary, and repository checks pass without broadcasting.

- [ ] **Step 8: Perform an explicit secret and scope audit**

Run: `rg -n "CKB_PRIVKEY|SignerCkbPrivateKey|process\.env" demo/dist demo/src/client demo/src/shared`

Expected: no matches in `demo/dist`, client, or shared code. Any allowed matches exist only in `demo/src/server/config.ts`, `demo/src/server/index.ts`, tests, and operator documentation.

Run: `git status --short`

Expected: implementation files plus the user-owned untracked `deploy/testnet-deployments.json`; do not stage the manifest.

- [ ] **Step 9: Commit browser verification and documentation**

```bash
git add demo/test/fixtures/mock-server.ts demo/test/browser/demo.spec.ts demo/test/browser/real-testnet.spec.ts demo/scripts/check-client-bundle.mjs demo/README.md README.md
git commit -m "Verify and document passkey demo"
```

## Final Acceptance Gate

After all task commits:

- [ ] Regenerate `vectors/frontend-v1.json` to `/tmp` and compare it byte-for-byte.
- [ ] Run all no-broadcast commands from Task 12 Step 7.
- [ ] Review `git log --oneline` and confirm each task is independently revertible.
- [ ] Confirm `git status --short` contains no accidental secret, `.env`, browser state, test artifact, or staged deployment manifest.
- [ ] Manually start the API with a hidden-prompt testnet key and verify that startup logs contain only the funder address, network, and public balance.
- [ ] Run the opt-in real-testnet browser test only after reviewing its printed capacity plan and ensuring the account manifest does not conflict with an existing credential.
- [ ] Open the resulting account and spend transaction in the CKB testnet explorer and confirm the AccountLock change remains live.
- [ ] Stop both development processes and run `unset CKB_PRIVKEY`.
