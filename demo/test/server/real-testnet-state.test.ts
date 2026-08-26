import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  RecoveryDocumentSchema,
  RunDocumentSchema,
  archiveRealTestnetState,
  classifyPresence,
  credentialMatchesPasskey,
  createRealTestnetPaths,
  decideNextAction,
  loadDiskState,
  loadRecovery,
  saveRecovery,
  saveRun,
} from "../support/real-testnet-state.js";
import type { RecoveryDocument } from "../support/real-testnet-state.js";

const roots: string[] = [];

async function tempPaths() {
  const root = await mkdtemp(join(tmpdir(), "ckb-passkey-state-"));
  roots.push(root);
  return createRealTestnetPaths(root);
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const passkey = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey: `0x04${"11".repeat(64)}`,
  keyId: `0x${"22".repeat(32)}`,
  rpId: "localhost",
  origin: "http://localhost:5173",
  createdAt: "2026-08-26T00:00:00.000Z",
} satisfies RecoveryDocument["passkey"];

const credential = {
  credentialId: "AQIDBA==",
  isResidentCredential: true,
  rpId: "localhost",
  privateKey: "AQIDBA==", // synthetic schema fixture, not a usable PKCS#8 key
  userHandle: "BQYHCA==",
  signCount: 0,
} satisfies RecoveryDocument["credentials"][0];

const recovery = {
  schemaVersion: 1,
  network: "testnet",
  origin: "http://localhost:5173",
  rpId: "localhost",
  passkey,
  credentials: [credential],
  createdAt: "2026-08-26T00:00:00.000Z",
} satisfies RecoveryDocument;

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
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

describe("real-testnet recovery state", () => {
  it("atomically round-trips recovery with private permissions", async () => {
    const paths = await tempPaths();
    await saveRecovery(paths, recovery);

    expect(await loadRecovery(paths)).toEqual(recovery);
    expect((await lstat(paths.activeDir)).mode & 0o777).toBe(0o700);
    expect((await lstat(paths.recoveryPath)).mode & 0o777).toBe(0o600);
    expect(await readFile(paths.recoveryPath, "utf8")).not.toContain("CKB_PRIVKEY");
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

  it.each(["rootDir", "activeDir"] as const)("rejects a symlinked %s before recovery lookup", async (directory) => {
    const paths = await tempPaths();

    if (directory === "rootDir") {
      const target = join(dirname(paths.rootDir), "separate-state");
      await mkdir(dirname(paths.rootDir), { recursive: true, mode: 0o700 });
      await mkdir(target, { mode: 0o700 });
      await symlink(target, paths.rootDir);
    } else {
      const target = join(paths.rootDir, "separate-state");
      await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
      await mkdir(target, { mode: 0o700 });
      await symlink(target, paths.activeDir);
    }

    await expect(loadRecovery(paths)).rejects.toThrow(/symbolic link/i);
  });

  it.each(["rootDir", "activeDir"] as const)("rejects a group-accessible %s before recovery lookup", async (directory) => {
    const paths = await tempPaths();
    await mkdir(paths.activeDir, { recursive: true, mode: 0o700 });
    await chmod(paths[directory], 0o750);

    await expect(loadRecovery(paths)).rejects.toThrow(/permissions/i);
  });

  it("does not downgrade a symlinked empty active directory to fresh", async () => {
    const paths = await tempPaths();
    const target = join(paths.rootDir, "separate-state");
    await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
    await mkdir(target, { mode: 0o700 });
    await symlink(target, paths.activeDir);

    await expect(loadDiskState(paths)).rejects.toThrow(/recovery/i);
  });

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
