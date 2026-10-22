# Resumable Real-Testnet Passkey Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the funded CKB testnet browser flow resumable by persisting its virtual passkey and Chromium profile before account creation, while providing safe state reconciliation and explicit archival.

**Architecture:** Test-only support modules own schema validation, secure filesystem persistence, CDP virtual-authenticator capture/restore, and archival. The real Playwright spec launches a persistent Chromium context, chooses actions from authoritative disk/UI/chain state, records public hashes immediately, and never repeats a mutation whose hash is already known.

**Tech Stack:** TypeScript 5.9, Node.js 22 filesystem APIs, Zod 4, Playwright 1.55/CDP WebAuthn, Vitest 3, CCC 1.18.2, CKB public testnet.

**Spec:** `docs/superpowers/specs/2026-08-25-resumable-real-testnet-passkey-design.md`

## Global Constraints

- Network remains CKB public testnet only.
- Browser origin is exactly `http://localhost:5173`; WebAuthn RP ID is exactly `localhost`.
- `CKB_PRIVKEY` remains environment-only and must never be persisted, logged, or passed to browser code.
- `demo/.local/` is Git-ignored; active private directories use mode `0700`; recovery and run documents use mode `0600`.
- A live CDP credential private key is local testnet recovery material and must never appear in logs, errors, source fixtures, commits, or the production bundle; schema tests use only an obviously synthetic base64 value.
- Account creation is forbidden until a newly created credential has been atomically persisted and re-read successfully.
- A manifest without valid matching recovery state blocks before any browser or chain mutation.
- Known account or spend hashes are reconciled, never recreated or resubmitted.
- Normal test execution never removes active state or archives.
- Permanent deletion is not implemented; archival is an explicit recoverable move.
- Every behavior change follows red-green TDD and receives an inline code/security review because subagents are not assumed available.

## File Structure

- Create `demo/test/support/real-testnet-state.ts`: recovery/run schemas, path model, state classification, safe persistence, and stage decisions.
- Create `demo/test/server/real-testnet-state.test.ts`: pure state matrix and filesystem-safety tests using temporary directories only.
- Create `demo/test/support/archive-real-testnet.ts`: recoverable archive primitive and CLI entry point.
- Create `demo/test/browser/support/virtual-authenticator.ts`: CDP authenticator creation, credential capture, credential restore, and localStorage restoration.
- Modify `demo/test/browser/demo.spec.ts`: deterministic real-CDP backup/restore coverage.
- Modify `demo/test/browser/real-testnet.spec.ts`: persistent context and resumable live orchestration.
- Modify `demo/tsconfig.node.json`: include `test/support` in Node type checking.
- Modify `demo/package.json`: add `testnet:archive`.
- Modify `.gitignore`: ignore `demo/.local/`.
- Modify `demo/README.md`: document persistence, recovery sensitivity, resume, archive, and deletion warning.

---

### Task 1: Define Recovery Documents, State Classification, and Mutation Decisions

**Files:**
- Create: `demo/test/support/real-testnet-state.ts`
- Create: `demo/test/server/real-testnet-state.test.ts`
- Modify: `demo/tsconfig.node.json`

**Interfaces:**
- Produces: `RealTestnetPaths`, `RecoveryDocument`, `RunDocument`, `DiskState`, `VisibleStage`, `NextAction`.
- Produces: `RecoveryDocumentSchema`, `RunDocumentSchema`, `createRealTestnetPaths()`, `classifyPresence()`, `credentialMatchesPasskey()`, `decideNextAction()`.
- Consumes: `PasskeyRecordSchema` and `AccountManifestSchema` from `demo/src/shared/schemas.ts`.

- [ ] **Step 1: Add `test/support` to Node type checking**

Add the directory to `demo/tsconfig.node.json`:

```json
"include": [
  "src/server",
  "src/shared",
  "test/browser",
  "test/fixtures",
  "test/server",
  "test/support",
  "vite.config.ts",
  "vitest.config.ts",
  "playwright.config.ts"
]
```

- [ ] **Step 2: Write failing schema and state-matrix tests**

Start `demo/test/server/real-testnet-state.test.ts` with literal fixtures. The CDP `binary` fields are base64 strings; the browser `PasskeyRecord.credentialId` is canonical base64url.

```ts
import { describe, expect, it } from "vitest";

import {
  RecoveryDocumentSchema,
  RunDocumentSchema,
  classifyPresence,
  credentialMatchesPasskey,
  decideNextAction,
} from "../support/real-testnet-state.js";

const passkey = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey: `0x04${"11".repeat(64)}`,
  keyId: `0x${"22".repeat(32)}`,
  rpId: "localhost",
  origin: "http://localhost:5173",
  createdAt: "2026-08-26T00:00:00.000Z",
};

const credential = {
  credentialId: "AQIDBA==",
  isResidentCredential: true,
  rpId: "localhost",
  privateKey: "AQIDBA==", // synthetic schema fixture, not a usable PKCS#8 key
  userHandle: "BQYHCA==",
  signCount: 0,
};

const recovery = {
  schemaVersion: 1,
  network: "testnet",
  origin: "http://localhost:5173",
  rpId: "localhost",
  passkey,
  credentials: [credential],
  createdAt: "2026-08-26T00:00:00.000Z",
};

describe("real-testnet recovery state", () => {
  it.each([
    [false, false, "fresh"],
    [false, true, "registered"],
    [true, true, "recoverable_account"],
    [true, false, "orphaned_account"],
  ] as const)("classifies manifest=%s recovery=%s as %s", (manifest, saved, expected) => {
    expect(classifyPresence({ manifestExists: manifest, recoveryExists: saved })).toBe(expected);
  });

  it("requires one localhost testnet credential matching the public passkey record", () => {
    expect(RecoveryDocumentSchema.parse(recovery)).toEqual(recovery);
    expect(credentialMatchesPasskey(credential, passkey)).toBe(true);
    expect(() => RecoveryDocumentSchema.parse({ ...recovery, origin: "https://example.com" }))
      .toThrow();
    expect(() => RecoveryDocumentSchema.parse({ ...recovery, credentials: [] })).toThrow();
  });

  it("accepts only public run stages and 32-byte transaction hashes", () => {
    expect(RunDocumentSchema.parse({
      schemaVersion: 1,
      stage: "account_committed",
      accountId: `0x${"33".repeat(32)}`,
      accountCreationHash: `0x${"44".repeat(32)}`,
      lastReconciledAt: "2026-08-26T00:00:00.000Z",
    }).stage).toBe("account_committed");
  });

  it.each([
    [{ disk: "fresh", visible: "create_passkey", runStage: undefined }, "register"],
    [{ disk: "registered", visible: "create_account", runStage: "registered" }, "bootstrap"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "registered" }, "reconcile_account"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "account_committed" }, "spend"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "spend_submitted" }, "reconcile_spend"],
    [{ disk: "orphaned_account", visible: "blocked", runStage: undefined }, "block"],
  ] as const)("chooses one non-duplicating action for %o", (input, expected) => {
    expect(decideNextAction(input)).toBe(expected);
  });
});
```

- [ ] **Step 3: Run the test and verify RED**

Run:

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
```

Expected: FAIL because `../support/real-testnet-state.js` does not exist.

- [ ] **Step 4: Implement schemas, path construction, and pure decisions**

Create `demo/test/support/real-testnet-state.ts` with these public types and literal security constraints:

```ts
import { dirname, resolve } from "node:path";
import { z } from "zod";

import { PasskeyRecordSchema } from "../../src/shared/schemas.js";

const HASH32 = /^0x[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const CdpCredentialSchema = z.object({
  credentialId: z.string().regex(BASE64),
  isResidentCredential: z.literal(true),
  rpId: z.literal("localhost"),
  privateKey: z.string().min(1).regex(BASE64),
  userHandle: z.string().regex(BASE64).optional(),
  signCount: z.number().int().nonnegative(),
  largeBlob: z.string().regex(BASE64).optional(),
  backupEligibility: z.boolean().optional(),
  backupState: z.boolean().optional(),
  userName: z.string().optional(),
  userDisplayName: z.string().optional(),
}).strict();

export const RecoveryDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  network: z.literal("testnet"),
  origin: z.literal("http://localhost:5173"),
  rpId: z.literal("localhost"),
  passkey: PasskeyRecordSchema,
  credentials: z.tuple([CdpCredentialSchema]),
  createdAt: z.string().datetime({ offset: true }),
}).strict().superRefine((value, context) => {
  if (!credentialMatchesPasskey(value.credentials[0], value.passkey)) {
    context.addIssue({ code: "custom", message: "credential ID does not match passkey record" });
  }
});

export const RunDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  stage: z.enum(["registered", "account_committed", "spend_submitted", "spend_committed"]),
  accountId: z.string().regex(HASH32).optional(),
  accountCreationHash: z.string().regex(HASH32).optional(),
  spendHash: z.string().regex(HASH32).optional(),
  lastReconciledAt: z.string().datetime({ offset: true }),
}).strict();

export type RecoveryDocument = z.infer<typeof RecoveryDocumentSchema>;
export type RunDocument = z.infer<typeof RunDocumentSchema>;
export type DiskState = "fresh" | "registered" | "recoverable_account" | "orphaned_account";
export type VisibleStage = "create_passkey" | "create_account" | "authorize_spend" | "submitted" | "committed" | "blocked";
export type NextAction = "register" | "bootstrap" | "reconcile_account" | "spend" | "reconcile_spend" | "complete" | "block";

export interface RealTestnetPaths {
  rootDir: string;
  activeDir: string;
  profileDir: string;
  recoveryPath: string;
  runPath: string;
  archivesDir: string;
  manifestPath: string;
}

export function createRealTestnetPaths(repoRoot: string): RealTestnetPaths {
  const rootDir = resolve(repoRoot, "demo/.local/real-testnet");
  const activeDir = resolve(rootDir, "active");
  return {
    rootDir,
    activeDir,
    profileDir: resolve(activeDir, "profile"),
    recoveryPath: resolve(activeDir, "recovery.json"),
    runPath: resolve(activeDir, "run.json"),
    archivesDir: resolve(rootDir, "archives"),
    manifestPath: resolve(repoRoot, "deploy/testnet-account.json"),
  };
}

export function credentialMatchesPasskey(
  credential: z.infer<typeof CdpCredentialSchema>,
  passkey: z.infer<typeof PasskeyRecordSchema>,
): boolean {
  return Buffer.from(credential.credentialId, "base64")
    .equals(Buffer.from(passkey.credentialId, "base64url"));
}

export function classifyPresence(input: { manifestExists: boolean; recoveryExists: boolean }): DiskState {
  if (input.manifestExists) return input.recoveryExists ? "recoverable_account" : "orphaned_account";
  return input.recoveryExists ? "registered" : "fresh";
}

export function decideNextAction(input: {
  disk: DiskState;
  visible: VisibleStage;
  runStage?: RunDocument["stage"];
}): NextAction {
  if (input.disk === "orphaned_account") return "block";
  if (input.disk === "fresh" && input.runStage !== undefined) return "block";
  if (input.runStage === "account_committed" && input.disk !== "recoverable_account") return "block";
  if (input.runStage === "spend_committed") {
    return input.disk === "recoverable_account" ? "complete" : "block";
  }
  if (input.runStage === "spend_submitted") {
    return input.disk === "recoverable_account" ? "reconcile_spend" : "block";
  }
  if (input.visible === "blocked" || input.visible === "submitted" || input.visible === "committed") {
    return "block";
  }
  if (input.disk === "fresh" && input.visible === "create_passkey") return "register";
  if (input.disk === "registered" && input.visible === "create_account") return "bootstrap";
  if (
    input.disk === "recoverable_account" &&
    input.visible === "authorize_spend" &&
    (input.runStage === undefined || input.runStage === "registered")
  ) return "reconcile_account";
  if (input.disk === "recoverable_account" && input.visible === "authorize_spend") return "spend";
  return "block";
}
```

- [ ] **Step 5: Run targeted tests and Node type checking**

Run:

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run typecheck
```

Expected: state tests PASS and both TypeScript configurations exit 0.

- [ ] **Step 6: Commit Task 1**

```bash
git add demo/tsconfig.node.json demo/test/support/real-testnet-state.ts demo/test/server/real-testnet-state.test.ts
git commit -m "Model resumable testnet passkey state"
```

---

### Task 2: Add Owner-Only Atomic Persistence

**Files:**
- Modify: `demo/test/support/real-testnet-state.ts`
- Modify: `demo/test/server/real-testnet-state.test.ts`

**Interfaces:**
- Consumes: `RealTestnetPaths`, `RecoveryDocumentSchema`, `RunDocumentSchema` from Task 1.
- Produces: `ensurePrivateStateDirectories()`, `loadRecovery()`, `saveRecovery()`, `loadRun()`, `saveRun()`, `loadDiskState()`.

- [ ] **Step 1: Write failing filesystem-safety tests**

Add Node-environment tests using a unique `mkdtemp()` root. Every test must delete only its own temporary root in `afterEach`.

```ts
import { chmod, lstat, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { afterEach } from "vitest";

const roots: string[] = [];
async function tempPaths() {
  const root = await mkdtemp(join(tmpdir(), "ckb-passkey-state-"));
  roots.push(root);
  return createRealTestnetPaths(root);
}
afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

it("atomically round-trips recovery with private permissions", async () => {
  const paths = await tempPaths();
  await saveRecovery(paths, recovery);
  expect(await loadRecovery(paths)).toEqual(recovery);
  expect((await lstat(paths.activeDir)).mode & 0o777).toBe(0o700);
  expect((await lstat(paths.recoveryPath)).mode & 0o777).toBe(0o600);
  expect((await readFile(paths.recoveryPath, "utf8"))).not.toContain("CKB_PRIVKEY");
});

it("rejects group-readable and symlinked recovery files", async () => {
  const paths = await tempPaths();
  await saveRecovery(paths, recovery);
  await chmod(paths.recoveryPath, 0o640);
  await expect(loadRecovery(paths)).rejects.toThrow(/permissions/i);

  const second = await tempPaths();
  await mkdir(second.activeDir, { recursive: true, mode: 0o700 });
  await symlink(paths.recoveryPath, second.recoveryPath);
  await expect(loadRecovery(second)).rejects.toThrow(/symbolic link/i);
});

it("never downgrades malformed recovery to a fresh state", async () => {
  const paths = await tempPaths();
  await mkdir(paths.activeDir, { recursive: true, mode: 0o700 });
  await writeFile(paths.recoveryPath, "{}\n", { mode: 0o600 });
  await expect(loadDiskState(paths)).rejects.toThrow(/recovery/i);
});
```

- [ ] **Step 2: Run the test and verify RED**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
```

Expected: FAIL because the persistence functions are not exported.

- [ ] **Step 3: Implement private directory and managed-file guards**

Add helpers that use `lstat`, reject symlinks, and check permission bits before reading:

```ts
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";

async function exists(path: string): Promise<boolean> {
  try { await lstat(path); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function rejectSymlink(path: string): Promise<void> {
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new Error(`Refusing symbolic link at ${path}`);
}

async function requirePrivateFile(path: string): Promise<void> {
  await rejectSymlink(path);
  const info = await lstat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error(`Recovery file has unsafe permissions at ${path}`);
  }
}

export async function ensurePrivateStateDirectories(paths: RealTestnetPaths): Promise<void> {
  await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.rootDir);
  await chmod(paths.rootDir, 0o700);
  await mkdir(paths.activeDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.activeDir);
  await chmod(paths.activeDir, 0o700);
  await mkdir(paths.profileDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.profileDir);
  await chmod(paths.profileDir, 0o700);
  await mkdir(paths.archivesDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.archivesDir);
  await chmod(paths.archivesDir, 0o700);
}
```

- [ ] **Step 4: Implement atomic schema-validated JSON writes**

The helper must create a unique same-directory temporary file with `wx`, sync it, rename it, chmod the final file, and validate the final read. It must remove only the temporary file it created when an error occurs.

```ts
async function writePrivateJson<T>(
  path: string,
  value: T,
  schema: z.ZodType<T>,
): Promise<T> {
  const verified = schema.parse(value);
  if (await exists(path)) await requirePrivateFile(path);
  const temporary = `${path}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(verified, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await chmod(path, 0o600);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); }
    finally { await directory.close(); }
    return schema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function readPrivateJson<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
  if (!(await exists(path))) return null;
  await requirePrivateFile(path);
  return schema.parse(JSON.parse(await readFile(path, "utf8")));
}

export async function saveRecovery(paths: RealTestnetPaths, value: RecoveryDocument) {
  await ensurePrivateStateDirectories(paths);
  return writePrivateJson(paths.recoveryPath, value, RecoveryDocumentSchema);
}
export async function loadRecovery(paths: RealTestnetPaths) {
  return readPrivateJson(paths.recoveryPath, RecoveryDocumentSchema);
}
export async function saveRun(paths: RealTestnetPaths, value: RunDocument) {
  await ensurePrivateStateDirectories(paths);
  return writePrivateJson(paths.runPath, value, RunDocumentSchema);
}
export async function loadRun(paths: RealTestnetPaths) {
  return readPrivateJson(paths.runPath, RunDocumentSchema);
}
export async function loadDiskState(paths: RealTestnetPaths) {
  const recovery = await loadRecovery(paths);
  const manifestExists = await exists(paths.manifestPath);
  return { kind: classifyPresence({ manifestExists, recoveryExists: recovery !== null }), recovery };
}
```

- [ ] **Step 5: Run targeted tests and type checking**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run typecheck
```

Expected: all state tests PASS; type checking exits 0.

- [ ] **Step 6: Commit Task 2**

```bash
git add demo/test/support/real-testnet-state.ts demo/test/server/real-testnet-state.test.ts
git commit -m "Persist testnet passkey recovery safely"
```

---

### Task 3: Implement Recoverable Archival

**Files:**
- Create: `demo/test/support/archive-real-testnet.ts`
- Modify: `demo/test/support/real-testnet-state.ts`
- Modify: `demo/test/server/real-testnet-state.test.ts`
- Modify: `demo/package.json`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `RealTestnetPaths`, `loadRecovery()`, `loadRun()`, `ensurePrivateStateDirectories()`.
- Produces: `ArchiveSummarySchema`, `archiveRealTestnetState(paths, now)`, CLI command `npm run testnet:archive`.

- [ ] **Step 1: Write failing complete-state and orphan-state archive tests**

Add public fixtures and helpers in the temporary-directory test module:

```ts
const accountId = `0x${"55".repeat(32)}`;
const manifest = {
  schema_version: 1,
  network: "testnet",
  account_id: accountId,
  account_lock: {
    code_hash: `0x${"66".repeat(32)}`,
    hash_type: "data2",
    args: `0x01${accountId.slice(2)}`,
  },
  type_id_args: `0x${"77".repeat(32)}`,
  state_out_point: { tx_hash: `0x${"88".repeat(32)}`, index: 0 },
  asset_out_point: { tx_hash: `0x${"88".repeat(32)}`, index: 1 },
  state_bytes: 177,
} as const;

const run = {
  schemaVersion: 1,
  stage: "account_committed",
  accountId,
  accountCreationHash: manifest.state_out_point.tx_hash,
  lastReconciledAt: "2026-08-26T00:00:00.000Z",
} as const;

async function writeFixtureManifest(path: string) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function pathExists(path: string) {
  try { await lstat(path); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}
```

```ts
it("archives active profile, recovery, run metadata, and manifest without deletion", async () => {
  const paths = await tempPaths();
  await saveRecovery(paths, recovery);
  await saveRun(paths, run);
  await writeFixtureManifest(paths.manifestPath);
  await writeFile(join(paths.profileDir, "profile-marker"), "kept\n", { mode: 0o600 });

  const result = await archiveRealTestnetState(paths, new Date("2026-08-26T01:02:03.000Z"));

  expect(result.summary.credentialAvailable).toBe(true);
  expect(await pathExists(paths.activeDir)).toBe(false);
  expect(await pathExists(paths.manifestPath)).toBe(false);
  expect(await pathExists(join(result.archiveDir, "active/profile/profile-marker"))).toBe(true);
  expect(await pathExists(join(result.archiveDir, "testnet-account.json"))).toBe(true);
});

it("archives the current orphan shape and records unavailable credential", async () => {
  const paths = await tempPaths();
  await writeFixtureManifest(paths.manifestPath);
  const result = await archiveRealTestnetState(paths, new Date("2026-08-26T01:02:03.000Z"));
  expect(result.summary).toMatchObject({ credentialAvailable: false, reason: "orphaned_account" });
});

it("refuses an archive-name collision without moving sources", async () => {
  const paths = await tempPaths();
  await writeFixtureManifest(paths.manifestPath);
  await archiveRealTestnetState(paths, new Date("2026-08-26T01:02:03.000Z"));
  await writeFixtureManifest(paths.manifestPath);
  await expect(archiveRealTestnetState(paths, new Date("2026-08-26T01:02:03.000Z")))
    .rejects.toThrow(/already exists/i);
  expect(await pathExists(paths.manifestPath)).toBe(true);
});
```

- [ ] **Step 2: Run the archive tests and verify RED**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
```

Expected: FAIL because `archiveRealTestnetState` is missing.

- [ ] **Step 3: Implement archive summary and rollback-safe moves**

Extend the shared-schema import to include `AccountManifestSchema`, and add `rmdir` to the `node:fs/promises` import. Add an `ArchiveSummarySchema` with only public fields. The manifest loader rejects symlinks and validates public JSON; the summary writer reuses the private atomic writer from Task 2:

```ts
async function loadOptionalAccountManifest(path: string) {
  if (!(await exists(path))) return null;
  await rejectSymlink(path);
  return AccountManifestSchema.parse(JSON.parse(await readFile(path, "utf8")));
}

async function writeArchiveSummary(path: string, value: z.infer<typeof ArchiveSummarySchema>) {
  return writePrivateJson(path, value, ArchiveSummarySchema);
}
```

Implement staging below the archive root, move the active directory wholesale, move the manifest, write `summary.json`, and rename staging to the final archive. On error, restore the manifest first and then the active directory, remove only the newly-created empty staging directory, and surface any rollback failure:

```ts
export const ArchiveSummarySchema = z.object({
  schemaVersion: z.literal(1),
  archivedAt: z.string().datetime({ offset: true }),
  accountId: z.string().regex(HASH32).nullable(),
  accountCreationHash: z.string().regex(HASH32).nullable(),
  credentialAvailable: z.boolean(),
  reason: z.enum(["explicit_archive", "orphaned_account"]),
}).strict();

export async function archiveRealTestnetState(paths: RealTestnetPaths, now: Date) {
  const disk = await loadDiskState(paths);
  const run = await loadRun(paths);
  const manifest = await loadOptionalAccountManifest(paths.manifestPath);
  if (disk.kind === "fresh" && run === null) throw new Error("No active testnet state to archive");

  await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.rootDir);
  await chmod(paths.rootDir, 0o700);
  await mkdir(paths.archivesDir, { recursive: true, mode: 0o700 });
  await rejectSymlink(paths.archivesDir);
  await chmod(paths.archivesDir, 0o700);

  const stamp = now.toISOString().replaceAll(":", "-");
  const suffix = manifest?.account_id.slice(2, 10) ?? "pre-account";
  const archiveDir = resolve(paths.archivesDir, `${stamp}-${suffix}`);
  const staging = `${archiveDir}.staging`;
  if (await exists(archiveDir) || await exists(staging)) throw new Error(`Archive already exists at ${archiveDir}`);

  await mkdir(staging, { mode: 0o700 });
  let movedActive = false;
  let movedManifest = false;
  try {
    if (await exists(paths.activeDir)) {
      await rename(paths.activeDir, resolve(staging, "active"));
      movedActive = true;
    }
    if (manifest !== null) {
      await rename(paths.manifestPath, resolve(staging, "testnet-account.json"));
      movedManifest = true;
    }
    const summary = ArchiveSummarySchema.parse({
      schemaVersion: 1,
      archivedAt: now.toISOString(),
      accountId: manifest?.account_id ?? run?.accountId ?? null,
      accountCreationHash: manifest?.state_out_point.tx_hash ?? run?.accountCreationHash ?? null,
      credentialAvailable: disk.recovery !== null,
      reason: disk.kind === "orphaned_account" ? "orphaned_account" : "explicit_archive",
    });
    await writeArchiveSummary(resolve(staging, "summary.json"), summary);
    await rename(staging, archiveDir);
    return { archiveDir, summary };
  } catch (error) {
    const rollbackErrors: unknown[] = [];
    if (movedManifest) {
      await rename(resolve(staging, "testnet-account.json"), paths.manifestPath)
        .catch((rollbackError) => rollbackErrors.push(rollbackError));
    }
    if (movedActive) {
      await rename(resolve(staging, "active"), paths.activeDir)
        .catch((rollbackError) => rollbackErrors.push(rollbackError));
    }
    await unlink(resolve(staging, "summary.json")).catch(() => undefined);
    await rmdir(staging).catch((rollbackError) => rollbackErrors.push(rollbackError));
    if (rollbackErrors.length > 0) {
      throw new AggregateError([error, ...rollbackErrors], "Archive failed and rollback was incomplete");
    }
    throw error;
  }
}
```

- [ ] **Step 4: Add the CLI, package command, and ignore rule**

`demo/test/support/archive-real-testnet.ts` resolves the repository root from `import.meta.url`, calls the archive function once, and prints only archive path, account ID, account hash, and credential availability:

```ts
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { archiveRealTestnetState, createRealTestnetPaths } from "./real-testnet-state.js";

const demoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = resolve(demoRoot, "..");
const result = await archiveRealTestnetState(createRealTestnetPaths(repoRoot), new Date());
console.log(`Archived local testnet state at ${result.archiveDir}`);
console.log(`Account ${result.summary.accountId ?? "not created"}`);
console.log(`Account creation ${result.summary.accountCreationHash ?? "not submitted"}`);
console.log(`Credential available ${result.summary.credentialAvailable ? "yes" : "no"}`);
```

Add to `demo/package.json`:

```json
"testnet:archive": "tsx test/support/archive-real-testnet.ts"
```

Add to `.gitignore`:

```gitignore
demo/.local/
```

- [ ] **Step 5: Run archive tests, type checks, and an ignored-path check**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run typecheck
git check-ignore -v demo/.local/real-testnet/active/recovery.json
```

Expected: tests PASS, type checks exit 0, and `git check-ignore` identifies the new ignore rule.

- [ ] **Step 6: Commit Task 3**

```bash
git add .gitignore demo/package.json demo/test/support/archive-real-testnet.ts demo/test/support/real-testnet-state.ts demo/test/server/real-testnet-state.test.ts
git commit -m "Archive local testnet passkey state"
```

---

### Task 4: Capture and Restore the Real CDP Virtual Credential

**Files:**
- Create: `demo/test/browser/support/virtual-authenticator.ts`
- Modify: `demo/test/browser/demo.spec.ts`
- Modify: `demo/test/support/real-testnet-state.ts`
- Modify: `demo/test/server/real-testnet-state.test.ts`

**Interfaces:**
- Consumes: `RecoveryDocument`, `RealTestnetPaths`, `saveRecovery()`, `PASSKEY_STORAGE_KEY`, `PasskeyRecordSchema`.
- Produces: `VirtualAuthenticatorHandle`, `installVirtualAuthenticator()`, `captureAndPersistRecovery()`, `addRecoveryInitScript()`.

- [ ] **Step 1: Add a pure restore-document test**

Add a test ensuring serialized recovery round-trips every CDP field, including private key and sign count, while any safe summary excludes the key:

```ts
it("preserves the CDP restore payload but redacts private material from summaries", () => {
  const parsed = RecoveryDocumentSchema.parse(recovery);
  expect(parsed.credentials[0]).toEqual(credential);
  expect(recoverySummary(parsed)).toEqual({
    schemaVersion: 1,
    network: "testnet",
    credentialId: passkey.credentialId,
    keyId: passkey.keyId,
    createdAt: recovery.createdAt,
  });
  expect(JSON.stringify(recoverySummary(parsed))).not.toContain(credential.privateKey);
});
```

- [ ] **Step 2: Add a failing deterministic browser round-trip test**

Refactor the existing `installVirtualAuthenticator` call sites to import the future helper, then add this test to `demo/test/browser/demo.spec.ts`:

```ts
test("backs up and restores the virtual passkey before a spend", async ({ page }, testInfo) => {
  const paths = createRealTestnetPaths(testInfo.outputPath("repo-root"));
  const first = await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();

  const recovery = await captureAndPersistRecovery(page, first, paths, new Date("2026-08-26T00:00:00.000Z"));
  await first.session.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: first.authenticatorId,
  });
  await installVirtualAuthenticator(page, { recovery });

  await page.getByRole("button", { name: "Create testnet account" }).click();
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
});
```

The test uses Playwright's per-test output directory, not `demo/.local`.

- [ ] **Step 3: Run targeted tests and verify RED**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run test:browser -- --grep "backs up and restores"
```

Expected: FAIL because the helper and recovery summary do not exist.

- [ ] **Step 4: Implement recovery summary and CDP helper**

`demo/test/browser/support/virtual-authenticator.ts` must use the exact CDP return value and validate before persistence:

```ts
import type { BrowserContext, CDPSession, Page } from "@playwright/test";

import { PASSKEY_STORAGE_KEY } from "../../../src/client/storage.js";
import { PasskeyRecordSchema } from "../../../src/shared/schemas.js";
import {
  RecoveryDocumentSchema,
  saveRecovery,
  type RealTestnetPaths,
  type RecoveryDocument,
} from "../../support/real-testnet-state.js";

export interface VirtualAuthenticatorHandle {
  authenticatorId: string;
  session: CDPSession;
}

export interface InstallVirtualAuthenticatorOptions {
  recovery?: RecoveryDocument | null;
  userVerified?: boolean;
  automaticPresence?: boolean;
}

export async function installVirtualAuthenticator(
  page: Page,
  options: InstallVirtualAuthenticatorOptions = {},
): Promise<VirtualAuthenticatorHandle> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  const { authenticatorId } = await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: options.userVerified ?? true,
      automaticPresenceSimulation: options.automaticPresence ?? true,
    },
  });
  for (const credential of options.recovery?.credentials ?? []) {
    await session.send("WebAuthn.addCredential", { authenticatorId, credential });
  }
  return { session, authenticatorId };
}

export async function captureAndPersistRecovery(
  page: Page,
  handle: VirtualAuthenticatorHandle,
  paths: RealTestnetPaths,
  now: Date,
): Promise<RecoveryDocument> {
  const serialized = await page.evaluate((key) => localStorage.getItem(key), PASSKEY_STORAGE_KEY);
  if (serialized === null) throw new Error("Passkey record is unavailable after registration");
  const passkey = PasskeyRecordSchema.parse(JSON.parse(serialized));
  const { credentials } = await handle.session.send("WebAuthn.getCredentials", {
    authenticatorId: handle.authenticatorId,
  });
  const recovery = RecoveryDocumentSchema.parse({
    schemaVersion: 1,
    network: "testnet",
    origin: "http://localhost:5173",
    rpId: "localhost",
    passkey,
    credentials,
    createdAt: now.toISOString(),
  });
  return saveRecovery(paths, recovery);
}

export async function addRecoveryInitScript(
  context: BrowserContext,
  recovery: RecoveryDocument,
): Promise<void> {
  await context.addInitScript(({ key, serialized }) => {
    const existing = localStorage.getItem(key);
    if (existing === null) localStorage.setItem(key, serialized);
    else if (existing !== serialized) throw new Error("Persistent passkey record conflicts with recovery");
  }, { key: PASSKEY_STORAGE_KEY, serialized: JSON.stringify(recovery.passkey) });
}
```

- [ ] **Step 5: Run the real-CDP round trip and all deterministic browser tests**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run test:browser
```

Expected: state tests PASS and all browser tests, including backup/restore, PASS with one worker.

- [ ] **Step 6: Commit Task 4**

```bash
git add demo/test/browser/support/virtual-authenticator.ts demo/test/browser/demo.spec.ts demo/test/support/real-testnet-state.ts demo/test/server/real-testnet-state.test.ts
git commit -m "Restore persisted virtual passkeys"
```

---

### Task 5: Make the Funded Browser Spec Persistent and Stage-Aware

**Files:**
- Modify: `demo/test/browser/real-testnet.spec.ts`
- Modify: `demo/test/support/real-testnet-state.ts`
- Modify: `demo/test/server/real-testnet-state.test.ts`

**Interfaces:**
- Consumes: all state and authenticator interfaces from Tasks 1-4, `ccc.ClientPublicTestnet`, Playwright `chromium.launchPersistentContext()`.
- Produces: `visibleStage(page)`, `reconcileKnownSpend(txHash)`, and a resumable real-testnet test that owns its persistent context.

- [ ] **Step 1: Write failing action-gate tests for duplicate prevention**

Extend the pure decision table with conflict cases:

```ts
it.each([
  [{ disk: "fresh", visible: "create_account", runStage: undefined }, "block"],
  [{ disk: "fresh", visible: "create_passkey", runStage: "registered" }, "block"],
  [{ disk: "registered", visible: "create_passkey", runStage: "registered" }, "block"],
  [{ disk: "registered", visible: "create_account", runStage: "account_committed" }, "block"],
  [{ disk: "recoverable_account", visible: "create_account", runStage: "account_committed" }, "block"],
  [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "spend_submitted" }, "reconcile_spend"],
  [{ disk: "recoverable_account", visible: "submitted", runStage: "spend_submitted" }, "reconcile_spend"],
] as const)("fails closed for conflicting or already-mutated states", (input, expected) => {
  expect(decideNextAction(input)).toBe(expected);
});
```

Add invariant tests so `account_committed` requires account ID and account hash, and both spend stages require spend hash:

```ts
it("requires public hashes before advancing run stages", () => {
  expect(() => RunDocumentSchema.parse({
    schemaVersion: 1,
    stage: "account_committed",
    lastReconciledAt: "2026-08-26T00:00:00.000Z",
  })).toThrow(/account identity and hash/i);
  expect(() => RunDocumentSchema.parse({
    schemaVersion: 1,
    stage: "spend_submitted",
    accountId: `0x${"33".repeat(32)}`,
    accountCreationHash: `0x${"44".repeat(32)}`,
    lastReconciledAt: "2026-08-26T00:00:00.000Z",
  })).toThrow(/spend hash/i);
});
```

- [ ] **Step 2: Run the state tests and verify RED**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
```

Expected: at least one decision or run-document invariant test FAILS before tightening the implementation.

- [ ] **Step 3: Implement invariant refinements and safe public run updates**

Add exact `superRefine` rules and a merge helper that never clears known hashes:

```ts
export const RunDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  stage: z.enum(["registered", "account_committed", "spend_submitted", "spend_committed"]),
  accountId: z.string().regex(HASH32).optional(),
  accountCreationHash: z.string().regex(HASH32).optional(),
  spendHash: z.string().regex(HASH32).optional(),
  lastReconciledAt: z.string().datetime({ offset: true }),
}).strict().superRefine((value, context) => {
  if (value.stage !== "registered" && (!value.accountId || !value.accountCreationHash)) {
    context.addIssue({ code: "custom", message: `${value.stage} requires account identity and hash` });
  }
  if (
    (value.stage === "spend_submitted" || value.stage === "spend_committed") &&
    !value.spendHash
  ) {
    context.addIssue({ code: "custom", message: `${value.stage} requires a spend hash` });
  }
});

export function mergeRun(current: RunDocument | null, next: RunDocument): RunDocument {
  if (current?.accountCreationHash && next.accountCreationHash !== current.accountCreationHash) {
    throw new Error("Account creation hash cannot change");
  }
  if (current?.spendHash && next.spendHash !== current.spendHash) {
    throw new Error("Spend hash cannot change");
  }
  return RunDocumentSchema.parse({ ...current, ...next });
}
```

- [ ] **Step 4: Refactor the live test to own a persistent context**

Replace the injected ephemeral `page` with a persistent context. Resolve paths from the repository root, load state before launch, restore localStorage before navigation, and close the context only in `finally`:

```ts
import { ccc } from "@ckb-ccc/core";
import { chromium, expect, test, type Page } from "@playwright/test";
import { lstat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { AccountManifestSchema, type AccountManifest } from "../../src/shared/schemas.js";

import {
  createRealTestnetPaths,
  decideNextAction,
  ensurePrivateStateDirectories,
  loadDiskState,
  loadRecovery,
  loadRun,
  mergeRun,
  saveRun,
  type RealTestnetPaths,
  type RunDocument,
  type VisibleStage,
} from "../support/real-testnet-state.js";
import {
  addRecoveryInitScript,
  captureAndPersistRecovery,
  installVirtualAuthenticator,
  type VirtualAuthenticatorHandle,
} from "./support/virtual-authenticator.js";

const demoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = resolve(demoRoot, "..");
const paths = createRealTestnetPaths(repoRoot);

test("completes or resumes the passkey account and fixed spend on CKB testnet", async () => {
  test.setTimeout(20 * 60 * 1_000);
  await ensurePrivateStateDirectories(paths);
  const disk = await loadDiskState(paths);
  if (disk.kind === "orphaned_account") {
    throw new Error("Active account manifest has no recoverable passkey; archive it before a funded run");
  }

  const context = await chromium.launchPersistentContext(paths.profileDir, {
    baseURL: "http://localhost:5173",
    headless: true,
  });
  const page = context.pages()[0] ?? await context.newPage();
  let run = await loadRun(paths);
  try {
    if (disk.recovery) await addRecoveryInitScript(context, disk.recovery);
    const authenticator = await installVirtualAuthenticator(page, { recovery: disk.recovery });
    await page.goto("/");
    await executeResumableFlow(page, authenticator, paths, run);
  } catch (error) {
    console.error(await safeFailureSummary(page, paths));
    throw error;
  } finally {
    await context.close();
  }
});
```

- [ ] **Step 5: Implement visible-stage detection and fresh registration**

`visibleStage()` checks only known accessible headings and returns `blocked` for the safety screen or any visible alert. This makes a failed live-cell preparation non-authorizing. For `register`, click registration, capture and persist the credential, save run stage `registered`, re-read recovery, and only then continue:

```ts
async function visibleStage(page: Page): Promise<VisibleStage> {
  if (
    await page.getByRole("heading", { name: "Local setup is blocked" }).isVisible() ||
    await page.getByRole("alert").first().isVisible()
  ) return "blocked";
  const candidates: [VisibleStage, string][] = [
    ["create_passkey", "Create your passkey"],
    ["create_account", "Create your testnet account"],
    ["authorize_spend", "Authorize your first spend"],
    ["submitted", "Transaction submitted"],
    ["committed", "Spend committed"],
  ];
  for (const [stage, heading] of candidates) {
    if (await page.getByRole("heading", { name: heading }).isVisible()) return stage;
  }
  throw new Error("No recognized real-testnet stage is visible");
}
```

The flow driver performs at most four state transitions (registration, bootstrap,
submission, reconciliation) and re-reads disk/UI state before each transition. A known
spend hash is reconciled before consulting the UI, so an old disabled page can never
cause resubmission:

```ts
async function executeResumableFlow(
  page: Page,
  authenticator: VirtualAuthenticatorHandle,
  paths: RealTestnetPaths,
  initialRun: RunDocument | null,
): Promise<void> {
  let run = initialRun;
  for (let transition = 0; transition < 4; transition += 1) {
    if (run?.spendHash) {
      await reconcileKnownSpend(run.spendHash);
      run = mergeRun(run, {
        ...run,
        stage: "spend_committed",
        lastReconciledAt: new Date().toISOString(),
      });
      await saveRun(paths, run);
      return;
    }

    const currentDisk = await loadDiskState(paths);
    const stage = await visibleStage(page);
    const action = decideNextAction({ disk: currentDisk.kind, visible: stage, runStage: run?.stage });

    if (action === "register") {
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
      const saved = await captureAndPersistRecovery(page, authenticator, paths, new Date());
      if ((await loadRecovery(paths))?.passkey.credentialId !== saved.passkey.credentialId) {
        throw new Error("Persisted recovery could not be verified");
      }
      run = await saveRun(paths, {
        schemaVersion: 1,
        stage: "registered",
        lastReconciledAt: new Date().toISOString(),
      });
      continue;
    }
    if (action === "bootstrap") {
      run = await bootstrapAccount(page, paths, run);
      continue;
    }
    if (action === "reconcile_account") {
      const manifest = await readAccountManifest(page);
      run = await saveRun(paths, mergeRun(run, {
        schemaVersion: 1,
        stage: "account_committed",
        accountId: manifest.account_id,
        accountCreationHash: manifest.state_out_point.tx_hash,
        lastReconciledAt: new Date().toISOString(),
      }));
      continue;
    }
    if (action === "spend") {
      await submitAndCommitSpend(page, paths, run);
      return;
    }
    if (action === "block" && currentDisk.kind === "recoverable_account") {
      await explainBlockedAccount(page);
    }
    throw new Error(`Refusing unsafe real-testnet transition: ${action}`);
  }
  throw new Error("Real-testnet state did not converge within four transitions");
}
```

- [ ] **Step 6: Implement bootstrap, spend, and hash persistence**

Replace the existing account-hash reader with `readAccountManifest(page)`, which fetches
`/api/account` and parses the response with `AccountManifestSchema`. Use the existing
capacity plan and UI locators in these two transition helpers:

```ts
async function readAccountManifest(page: Page): Promise<AccountManifest> {
  const value: unknown = await page.evaluate(async () => {
    const response = await fetch("/api/account", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`account manifest request failed with ${response.status}`);
    return response.json();
  });
  return AccountManifestSchema.parse(value);
}

async function bootstrapAccount(
  page: Page,
  paths: RealTestnetPaths,
  run: RunDocument | null,
): Promise<RunDocument> {
  if (run === null) {
    run = await saveRun(paths, {
      schemaVersion: 1,
      stage: "registered",
      lastReconciledAt: new Date().toISOString(),
    });
  }
  if (run.stage !== "registered") throw new Error("Bootstrap requires registered run state");
  printCapacityPlan();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await expect(page.getByRole("heading", { name: "Authorize your first spend" }))
    .toBeVisible({ timeout: 10 * 60 * 1_000 });
  const manifest = await readAccountManifest(page);
  const next = mergeRun(run, {
    schemaVersion: 1,
    stage: "account_committed",
    accountId: manifest.account_id,
    accountCreationHash: manifest.state_out_point.tx_hash,
    lastReconciledAt: new Date().toISOString(),
  });
  await saveRun(paths, next);
  console.log(`Committed account creation transaction: ${next.accountCreationHash}`);
  return next;
}

async function submitAndCommitSpend(
  page: Page,
  paths: RealTestnetPaths,
  run: RunDocument | null,
): Promise<RunDocument> {
  if (run?.stage !== "account_committed") throw new Error("Spend requires committed account state");
  const authorize = page.getByRole("button", { name: "Authorize 100 CKB spend" });
  await expect(authorize).toBeEnabled({ timeout: 2 * 60 * 1_000 });
  if (await page.getByRole("alert").first().isVisible()) {
    throw new Error("Spend preparation is blocked; refusing authorization");
  }
  await authorize.click();
  await expect(page.getByRole("heading", { name: "Transaction submitted" }))
    .toBeVisible({ timeout: 2 * 60 * 1_000 });
  const spendHash = await readDisplayedSpendHash(page);
  const submitted = mergeRun(run, {
    ...run,
    schemaVersion: 1,
    stage: "spend_submitted",
    spendHash,
    lastReconciledAt: new Date().toISOString(),
  });
  await saveRun(paths, submitted);
  console.log(`Submitted spend transaction: ${spendHash}`);
  await expect(page.getByRole("heading", { name: "Spend committed" }))
    .toBeVisible({ timeout: 10 * 60 * 1_000 });
  const committed = mergeRun(submitted, {
    ...submitted,
    stage: "spend_committed",
    lastReconciledAt: new Date().toISOString(),
  });
  await saveRun(paths, committed);
  return committed;
}
```

- [ ] **Step 7: Implement read-only reconciliation for a known spend hash**

When `run.spendHash` exists, do not click the authorization button. Query the public client, wait only for the known hash, and require output index 1 live:

```ts
async function reconcileKnownSpend(txHash: `0x${string}`): Promise<void> {
  const client = new ccc.ClientPublicTestnet();
  const response = await client.getTransaction(txHash);
  if (response === undefined) throw new Error(`Known spend ${txHash} is unavailable`);
  if (response.status === "rejected") throw new Error(`Known spend ${txHash} was rejected`);
  if (response.status !== "committed") await client.waitTransaction(txHash, 0, 300_000);
  const change = await client.getCellLive({ txHash, index: 1 }, true, true);
  if (change === undefined) throw new Error(`Known spend ${txHash} has no live AccountLock change`);
}
```

For the forensic case where the original manifest input is dead but no spend hash was
saved, perform only a live-cell query and stop with the public outpoint. Never click,
sign, or search for a replacement input:

```ts
async function explainBlockedAccount(page: Page): Promise<never> {
  const manifest = await readAccountManifest(page);
  const outPoint = {
    txHash: manifest.asset_out_point.tx_hash,
    index: manifest.asset_out_point.index,
  } as const;
  const client = new ccc.ClientPublicTestnet();
  const live = await client.getCellLive(outPoint, true, true);
  if (live === undefined) {
    throw new Error(
      `Account asset ${outPoint.txHash}:${outPoint.index} is dead and no spend hash was preserved; manual read-only reconciliation is required`,
    );
  }
  throw new Error(
    `UI blocked while account asset ${outPoint.txHash}:${outPoint.index} remains live; refusing authorization`,
  );
}
```

Update `run.json` to `spend_committed` after successful known-hash reconciliation. The
safe failure summary may include hashes, the visible heading/alert, and public paths,
but never stringify recovery or a CDP credential.

Implement the reporter from Step 4 so even malformed recovery cannot mask the original
failure and only preservation booleans—not file contents—are emitted:

```ts
async function pathExists(path: string): Promise<boolean> {
  try { await lstat(path); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function safeFailureSummary(page: Page, paths: RealTestnetPaths): Promise<string> {
  const run = await loadRun(paths).catch(() => null);
  const disk = await loadDiskState(paths).then((value) => value.kind).catch(() => "unreadable");
  const heading = await page.getByRole("heading").first().textContent().catch(() => null);
  const alert = await page.getByRole("alert").first().textContent().catch(() => null);
  const recoveryPreserved = await pathExists(paths.recoveryPath).catch(() => false);
  const profilePreserved = await pathExists(paths.profileDir).catch(() => false);
  const nextAction = disk === "orphaned_account"
    ? "archive"
    : run?.spendHash
      ? "reconcile known spend"
      : recoveryPreserved
        ? "resume"
        : "inspect before restarting registration";
  return JSON.stringify({
    disk,
    heading: heading?.trim() || null,
    alert: alert?.trim() || null,
    accountCreationHash: run?.accountCreationHash ?? null,
    spendHash: run?.spendHash ?? null,
    recoveryPreserved,
    profilePreserved,
    nextAction,
  });
}
```

- [ ] **Step 8: Run targeted tests, skip gate, browser suite, and type checks**

```bash
npm --prefix demo test -- --run test/server/real-testnet-state.test.ts
npm --prefix demo run test:testnet
npm --prefix demo run test:browser
npm --prefix demo run typecheck
```

Expected: unit and deterministic browser tests PASS; the real test is SKIPPED without all three live gates; type checks exit 0.

- [ ] **Step 9: Commit Task 5**

```bash
git add demo/test/browser/real-testnet.spec.ts demo/test/support/real-testnet-state.ts demo/test/server/real-testnet-state.test.ts
git commit -m "Resume funded passkey browser flows"
```

---

### Task 6: Document Recovery and Run the Complete Deterministic Gate

**Files:**
- Modify: `demo/README.md`
- Verify: all files changed in Tasks 1-5

**Interfaces:**
- Consumes: final package commands, paths, and lifecycle from Tasks 1-5.
- Produces: operator instructions that never expose either private key.

- [ ] **Step 1: Document the persistent recovery boundary**

Add a section after the safe startup instructions covering:

```markdown
## Resumable funded browser test

The real-testnet test stores its dedicated Chromium profile and a plaintext,
testnet-only virtual WebAuthn private key below `demo/.local/real-testnet/active`.
The directory is Git-ignored and owner-only. Anyone who copies `recovery.json` can
authorize the remaining capacity in that testnet account.

Never paste, commit, upload, screenshot, or attach files from `demo/.local/`.
Do not remove the profile or recovery file while `deploy/testnet-account.json` is
active. A manifest without its recovery credential is intentionally blocked.

Re-run the same `npm run test:testnet` command after an interruption. The harness
restores the same credential and reconciles known hashes instead of creating or
submitting again.

After stopping all demo/test processes, archive active local state with:

    npm run testnet:archive

Archive moves local state and the active public manifest into an ignored timestamped
directory. It does not delete credentials or change on-chain cells.
```

- [ ] **Step 2: Review all changes for secret exposure and unsafe deletion**

Run:

```bash
git diff --check
git diff --stat main...HEAD
rg -n "privateKey|CKB_PRIVKEY|recovery\.json|rm\(" demo/test demo/README.md .gitignore --glob '!node_modules/**'
```

Review each match. Accept `privateKey` only in the strict test-only schema/CDP payload, accept `CKB_PRIVKEY` only in existing environment gate/docs, and reject any logging or recursive removal of active/archived state.

- [ ] **Step 3: Run the complete deterministic gate**

```bash
npm --prefix demo run check
npm --prefix demo run test:testnet
git diff --check
git status --short
```

Expected:

- 0 type errors;
- all Vitest tests PASS;
- all deterministic Playwright tests PASS;
- production build and bundle audit PASS;
- real test SKIPPED without explicit live gates;
- `deploy/testnet-account.json` remains the only untracked incident artifact before archival.

- [ ] **Step 4: Perform inline code and security review**

Check these mutations explicitly:

- removing the `0600` permission check makes a unit test fail;
- replacing atomic rename with direct write makes the atomicity test fail;
- changing `localhost` or the credential ID makes recovery validation fail;
- setting a known spend hash still chooses `reconcile_spend`, never `spend`;
- manifest-without-recovery always chooses `block`;
- no production client module imports `test/support` or `node:fs`.

- [ ] **Step 5: Commit Task 6**

```bash
git add demo/README.md
git commit -m "Document resumable testnet passkeys"
```

---

### Task 7: Archive the Existing Orphaned Account Manifest

**Files:**
- Move at runtime: `deploy/testnet-account.json` to ignored `demo/.local/real-testnet/archives/<timestamp>-a449c9a7/testnet-account.json`
- Create at runtime: ignored archive `summary.json`

**Interfaces:**
- Consumes: `npm run testnet:archive` from Task 3.
- Produces: no active manifest, one ignored forensic archive, no chain mutation.

- [ ] **Step 1: Reconfirm both orphaned outpoints before archival**

Use read-only CKB testnet RPC `get_live_cell` for transaction
`0xc5aadcce997ac2eb6329153209032d0a66b86cc5f25ded7335d7d8b7f3dbeceb`, indices `0x0` and `0x1`.

Expected: both results have `status: "live"`, with capacities 316 CKB and 200 CKB.

- [ ] **Step 2: Run the explicit archive command**

```bash
cd demo
npm run testnet:archive
```

Expected output includes:

```text
Account 0xa449c9a77112eee77f89b20576374d010408c9074c689dd1a0c8bf75046d55b4
Account creation 0xc5aadcce997ac2eb6329153209032d0a66b86cc5f25ded7335d7d8b7f3dbeceb
Credential available no
```

- [ ] **Step 3: Verify archival without exposing ignored contents**

```bash
test ! -e deploy/testnet-account.json
git status --short
git status --short --ignored demo/.local/
```

Expected: active manifest is absent, normal Git status is clean, and the archive appears only as ignored local state.

- [ ] **Step 4: Do not commit archive material**

No `git add` or commit is performed for Task 7. Record the public archive path in the implementation handoff only; never print or inspect a `recovery.json` from future recoverable archives.

---

### Task 8: Run One Funded Flow, Prove Resume, Then Push and Open the PR

**Files:**
- Create at runtime: ignored `demo/.local/real-testnet/active/profile/`
- Create at runtime: ignored `demo/.local/real-testnet/active/recovery.json`
- Create at runtime: ignored `demo/.local/real-testnet/active/run.json`
- Create at runtime: untracked public `deploy/testnet-account.json`
- No committed code changes expected unless live evidence reveals a new defect.

**Interfaces:**
- Consumes: the entire implemented harness.
- Produces: committed account and spend hashes, retained recoverable account state, pushed feature branch, and PR.

- [ ] **Step 1: Enter the testnet funding key without shell-history exposure**

```bash
cd /home/phill/ckb-passkey/ckb-crypto-agile-account-reference-v0.1/demo
read -rsp "CKB testnet private key (0x…): " CKB_PRIVKEY
echo
export CKB_PRIVKEY RUN_CKB_TESTNET=1
```

Never print the variable or place it in a command argument, `.env`, recovery file, log, screenshot, chat, or commit.

- [ ] **Step 2: Run the funded resumable spec exactly once**

```bash
npm run test:testnet
```

Expected sequence:

```text
Committed account creation transaction: 0x...
Submitted spend transaction: 0x...
1 passed
```

On any failure, do not archive, delete, or start a fresh flow. Preserve the profile, recovery, run document, manifest, and public hashes; diagnose and resume with the same command.

- [ ] **Step 3: Verify active recovery without printing it**

```bash
stat -c '%a %n' .local/real-testnet/active .local/real-testnet/active/recovery.json .local/real-testnet/active/run.json
git check-ignore -v .local/real-testnet/active/recovery.json
```

Expected: active directory `700`, both JSON files `600`, and recovery is ignored. Do not run `cat`, `sed`, `jq`, or any command that prints `recovery.json`.

- [ ] **Step 4: Verify public hashes and chain state**

Read only `deploy/testnet-account.json` and the public fields of `run.json`. Confirm:

- account creation hash matches both manifest outpoints;
- spend hash is present in run metadata;
- account creation and spend transactions are committed;
- spend output index 1 is a live AccountLock change with the displayed remaining capacity.

- [ ] **Step 5: Prove restart is read-only and resumable**

Run the same command again with the same exported environment:

```bash
npm run test:testnet
```

Expected: the harness restores the same credential, reconciles the known committed spend, exits PASS, and prints no new account-creation or spend-submission hash. Compare the known hashes and funder balance before/after to confirm no new transaction.

- [ ] **Step 6: Clear the funding key after all live checks**

```bash
unset CKB_PRIVKEY RUN_CKB_TESTNET
```

- [ ] **Step 7: Run final verification and secret audit**

```bash
npm --prefix demo run check
git diff --check
git status --short
git log --oneline main..HEAD
```

Expected: deterministic gate PASS; only the public active account manifest is untracked; local profile/recovery/run state remains ignored.

- [ ] **Step 8: Push the feature branch**

```bash
git push -u origin feat/abi-v1-conformance
```

- [ ] **Step 9: Open the pull request**

```bash
gh pr create \
  --base main \
  --head feat/abi-v1-conformance \
  --title "Add the resumable CKB passkey testnet demo" \
  --body "Implements the local WebAuthn P-256 AccountLock demo, published testnet integration, deterministic browser coverage, explicit custom-script transaction submission, and resumable owner-only testnet passkey state. Includes committed live account/spend verification evidence while keeping all private recovery material local and ignored."
```

Expected: GitHub returns the new PR URL. Do not add `deploy/testnet-account.json` or anything below `demo/.local/` to the commit or PR.

---

## Completion Checklist

- [ ] Each task followed RED → GREEN → targeted regression → commit.
- [ ] Recovery is written and re-read before funded account creation.
- [ ] Manifest-without-recovery blocks before mutation.
- [ ] Known hashes cannot be replaced or resubmitted.
- [ ] Credential and profile persist after failure and success.
- [ ] Active and archived recovery material is Git-ignored and owner-only.
- [ ] Existing orphaned manifest is archived without deletion or chain mutation.
- [ ] Complete deterministic verification passes.
- [ ] One fresh funded account/spend flow commits.
- [ ] A second run reconciles without new transactions.
- [ ] Funding environment variables are unset.
- [ ] Branch is pushed and PR is open.
