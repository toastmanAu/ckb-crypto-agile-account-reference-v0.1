import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rmdir,
  unlink,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { z } from "zod";

import { AccountManifestSchema, PasskeyRecordSchema } from "../../src/shared/schemas.js";

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

export const ArchiveSummarySchema = z.object({
  schemaVersion: z.literal(1),
  archivedAt: z.string().datetime({ offset: true }),
  accountId: z.string().regex(HASH32).nullable(),
  accountCreationHash: z.string().regex(HASH32).nullable(),
  credentialAvailable: z.boolean(),
  reason: z.enum(["explicit_archive", "orphaned_account"]),
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

export interface ArchiveOptions {
  beforeFinalDirectoryReservation?: (archiveDir: string) => void | Promise<void>;
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

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
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
    throw new Error(`Managed file has unsafe permissions at ${path}`);
  }
}

async function requirePrivateDirectory(path: string): Promise<void> {
  await rejectSymlink(path);
  const info = await lstat(path);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) {
    throw new Error(`State directory has unsafe permissions at ${path}`);
  }
}

async function validatePrivateStateDirectoriesForRead(paths: RealTestnetPaths): Promise<void> {
  if (await exists(paths.rootDir)) await requirePrivateDirectory(paths.rootDir);
  if (await exists(paths.activeDir)) await requirePrivateDirectory(paths.activeDir);
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

async function writePrivateJson<T>(
  path: string,
  value: T,
  schema: z.ZodType<T>,
): Promise<T> {
  const verified = schema.parse(value);
  if (await exists(path)) await requirePrivateFile(path);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryCreated = false;
  try {
    handle = await open(temporary, "wx", 0o600);
    temporaryCreated = true;
    await handle.writeFile(`${JSON.stringify(verified, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await chmod(path, 0o600);
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    return schema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (temporaryCreated) await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function readPrivateJson<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
  if (!(await exists(path))) return null;
  await requirePrivateFile(path);
  return schema.parse(JSON.parse(await readFile(path, "utf8")));
}

async function loadOptionalAccountManifest(path: string) {
  if (!(await exists(path))) return null;
  await rejectSymlink(path);
  return AccountManifestSchema.parse(JSON.parse(await readFile(path, "utf8")));
}

async function writeArchiveSummary(
  path: string,
  value: z.infer<typeof ArchiveSummarySchema>,
) {
  return writePrivateJson(path, value, ArchiveSummarySchema);
}

function inconsistentArchiveState(reason: string): never {
  throw new Error(`Inconsistent archive state: ${reason}`);
}

function validateArchiveState(input: {
  disk: Awaited<ReturnType<typeof loadDiskState>>;
  run: RunDocument | null;
  manifest: z.infer<typeof AccountManifestSchema> | null;
}): void {
  const actualDisk = classifyPresence({
    manifestExists: input.manifest !== null,
    recoveryExists: input.disk.recovery !== null,
  });
  if (actualDisk !== input.disk.kind) {
    inconsistentArchiveState("manifest changed while loading");
  }

  if (input.manifest === null) {
    if (
      input.disk.recovery !== null
      && input.run?.stage === "registered"
      && input.run.accountId === undefined
      && input.run.accountCreationHash === undefined
      && input.run.spendHash === undefined
    ) {
      return;
    }
    if (input.disk.kind === "fresh" && input.run === null) {
      throw new Error("No active testnet state to archive");
    }
    inconsistentArchiveState("account-stage run requires an account manifest");
  }

  if (input.disk.recovery === null && input.run === null) return;
  if (input.disk.recovery === null || input.run === null) {
    inconsistentArchiveState("account manifest, recovery, and run must be archived together");
  }
  if (input.run.stage === "registered") {
    inconsistentArchiveState("registered run cannot have an account manifest");
  }
  if (input.run.accountId !== input.manifest.account_id) {
    inconsistentArchiveState("run account ID does not match account manifest");
  }
  if (input.run.accountCreationHash !== input.manifest.state_out_point.tx_hash) {
    inconsistentArchiveState("run account creation hash does not match account manifest");
  }
}

export async function saveRecovery(paths: RealTestnetPaths, value: RecoveryDocument): Promise<RecoveryDocument> {
  await ensurePrivateStateDirectories(paths);
  return writePrivateJson(paths.recoveryPath, value, RecoveryDocumentSchema);
}

export async function loadRecovery(paths: RealTestnetPaths): Promise<RecoveryDocument | null> {
  await validatePrivateStateDirectoriesForRead(paths);
  return readPrivateJson(paths.recoveryPath, RecoveryDocumentSchema);
}

export async function saveRun(paths: RealTestnetPaths, value: RunDocument): Promise<RunDocument> {
  await ensurePrivateStateDirectories(paths);
  return writePrivateJson(paths.runPath, value, RunDocumentSchema);
}

export async function loadRun(paths: RealTestnetPaths): Promise<RunDocument | null> {
  await validatePrivateStateDirectoriesForRead(paths);
  return readPrivateJson(paths.runPath, RunDocumentSchema);
}

export async function loadDiskState(paths: RealTestnetPaths): Promise<{
  kind: DiskState;
  recovery: RecoveryDocument | null;
}> {
  let recovery: RecoveryDocument | null;
  try {
    recovery = await loadRecovery(paths);
  } catch (error) {
    throw new Error("Unable to load recovery state", { cause: error });
  }
  const manifestExists = await exists(paths.manifestPath);
  return { kind: classifyPresence({ manifestExists, recoveryExists: recovery !== null }), recovery };
}

export async function archiveRealTestnetState(
  paths: RealTestnetPaths,
  now: Date,
  options: ArchiveOptions = {},
) {
  const disk = await loadDiskState(paths);
  const run = await loadRun(paths);
  const manifest = await loadOptionalAccountManifest(paths.manifestPath);
  validateArchiveState({ disk, run, manifest });

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
  if (await exists(staging)) {
    throw new Error(`Archive already exists at ${archiveDir}`);
  }

  await mkdir(staging, { mode: 0o700 });
  let activeLocation: "staging" | "archive" | null = null;
  let manifestLocation: "staging" | "archive" | null = null;
  let summaryLocation: "staging" | "archive" | null = null;
  let reservedArchive = false;
  try {
    if (await exists(paths.activeDir)) {
      await rename(paths.activeDir, resolve(staging, "active"));
      activeLocation = "staging";
    }
    if (manifest !== null) {
      await rename(paths.manifestPath, resolve(staging, "testnet-account.json"));
      manifestLocation = "staging";
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
    summaryLocation = "staging";
    await options.beforeFinalDirectoryReservation?.(archiveDir);
    try {
      await mkdir(archiveDir, { mode: 0o700 });
      reservedArchive = true;
      await chmod(archiveDir, 0o700);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new Error(`Archive already exists at ${archiveDir}`, { cause: error });
      }
      throw error;
    }
    if (activeLocation === "staging") {
      await rename(resolve(staging, "active"), resolve(archiveDir, "active"));
      activeLocation = "archive";
    }
    if (manifestLocation === "staging") {
      await rename(resolve(staging, "testnet-account.json"), resolve(archiveDir, "testnet-account.json"));
      manifestLocation = "archive";
    }
    await rename(resolve(staging, "summary.json"), resolve(archiveDir, "summary.json"));
    summaryLocation = "archive";
    await rmdir(staging);
    return { archiveDir, summary };
  } catch (error) {
    const rollbackErrors: unknown[] = [];
    if (manifestLocation !== null) {
      const manifestSource = resolve(
        manifestLocation === "archive" ? archiveDir : staging,
        "testnet-account.json",
      );
      await rename(manifestSource, paths.manifestPath)
        .catch((rollbackError) => rollbackErrors.push(rollbackError));
    }
    if (activeLocation !== null) {
      const activeSource = resolve(activeLocation === "archive" ? archiveDir : staging, "active");
      await rename(activeSource, paths.activeDir)
        .catch((rollbackError) => rollbackErrors.push(rollbackError));
    }
    if (summaryLocation === "staging") await unlink(resolve(staging, "summary.json")).catch(() => undefined);
    if (summaryLocation === "archive") await unlink(resolve(archiveDir, "summary.json")).catch(() => undefined);
    await rmdir(staging).catch((rollbackError) => rollbackErrors.push(rollbackError));
    if (reservedArchive) await rmdir(archiveDir).catch((rollbackError) => rollbackErrors.push(rollbackError));
    if (rollbackErrors.length > 0) {
      throw new AggregateError([error, ...rollbackErrors], "Archive failed and rollback was incomplete");
    }
    throw error;
  }
}

export function credentialMatchesPasskey(
  credential: Pick<z.infer<typeof CdpCredentialSchema>, "credentialId">,
  passkey: Pick<z.infer<typeof PasskeyRecordSchema>, "credentialId">,
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
