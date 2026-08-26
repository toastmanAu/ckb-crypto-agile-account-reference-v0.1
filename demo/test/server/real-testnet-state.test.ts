import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  RecoveryDocumentSchema,
  RunDocumentSchema,
  classifyPresence,
  credentialMatchesPasskey,
  createRealTestnetPaths,
  decideNextAction,
  loadDiskState,
  loadRecovery,
  saveRecovery,
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
