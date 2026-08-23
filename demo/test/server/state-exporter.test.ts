import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { BootstrapRequest, DeploymentManifest } from "../../src/shared/schemas.js";
import {
  exportAccountState,
  type ExporterDeps,
  type SpawnProcessOptions,
} from "../../src/server/state-exporter.js";

const PUBLIC_KEY = `0x04${"11".repeat(64)}`;
const KEY_ID = "0xd7ef93190b2298d3def2e6ecba04747ae5ca7ec7eb1a76e2138a588580440d64";
const RP_ID_HASH = "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763";
const ORIGIN_HASH = "4e90ec8f9d9b8d5bd3877ac003797738ff48419fcf8f97821a875ea4671955b6";
const VERIFIER_HASH =
  "0x376a3e1bfefc57d63cff2e5d022283800fb6b5f014b5edac4be573d58a7b124a";

const request: BootstrapRequest = { publicKey: PUBLIC_KEY, credentialId: "AQIDBA" };
const deployment = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: `0x${"aa".repeat(32)}`,
      hashType: "data2",
      txHash: `0x${"bb".repeat(32)}`,
      index: 0,
      capacityShannons: "1",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: VERIFIER_HASH,
      hashType: "data2",
      txHash: `0x${"cc".repeat(32)}`,
      index: 0,
      capacityShannons: "1",
    },
  },
} satisfies DeploymentManifest;

function harness(options: { exitCode?: number; output?: Uint8Array; readError?: Error } = {}) {
  const tempDirectory = join(tmpdir(), "ckb-passkey-state-test");
  const writes: Array<{ path: string; data: string; options: { mode: number; flag: string } }> = [];
  const spawns: Array<{ command: string; args: readonly string[]; options: SpawnProcessOptions }> = [];
  const removed: string[] = [];

  const deps: ExporterDeps = {
    repoRoot: "/repo",
    deployment,
    processEnv: { PATH: "/usr/bin", CKB_PRIVKEY: "must-not-reach-cargo" },
    async makeTempDir() {
      return tempDirectory;
    },
    async writeFile(path, data, options) {
      writes.push({ path, data, options });
    },
    async spawnProcess(command, args, spawnOptions) {
      spawns.push({ command, args, options: spawnOptions });
      return { exitCode: options.exitCode ?? 0, stderr: "sensitive child detail" };
    },
    async readFile() {
      if (options.readError) throw options.readError;
      return options.output ?? Uint8Array.of(1, 2, 3);
    },
    async removeDir(path) {
      removed.push(path);
    },
  };
  return { deps, tempDirectory, writes, spawns, removed };
}

describe("exportAccountState", () => {
  it("recomputes the fixed P-256 account configuration and invokes Cargo directly", async () => {
    const run = harness();

    await expect(exportAccountState(request, run.deps)).resolves.toEqual(
      Uint8Array.of(1, 2, 3),
    );

    expect(run.writes).toHaveLength(1);
    expect(run.writes[0].options).toEqual({ mode: 0o600, flag: "wx" });
    const config = JSON.parse(run.writes[0].data);
    expect(config).toEqual({
      flags: 1,
      sequence: 0,
      spend_threshold: 1,
      rotate_threshold: 1,
      recovery_threshold: 1,
      recovery_since: 0,
      authenticators: [
        {
          slot: 0,
          algorithm_id: 1,
          capabilities: 7,
          weight: 1,
          verifier_hash_type: 0,
          verifier_abi: 1,
          verifier_code_hash: VERIFIER_HASH,
          key_id: KEY_ID,
          aux: `0x01${RP_ID_HASH}${ORIGIN_HASH}`,
        },
      ],
    });
    expect(config).not.toHaveProperty("credentialId");

    expect(run.spawns).toHaveLength(1);
    expect(run.spawns[0]).toEqual({
      command: "cargo",
      args: [
        "run",
        "-q",
        "-p",
        "ckb-account-host",
        "--example",
        "export_account_state",
        "--",
        join(run.tempDirectory, "account.json"),
        join(run.tempDirectory, "state.bin"),
      ],
      options: {
        cwd: "/repo",
        shell: false,
        env: { PATH: "/usr/bin" },
      },
    });
    expect(run.removed).toEqual([run.tempDirectory]);
  });

  it.each([
    ["Cargo failure", { exitCode: 1 }],
    ["empty output", { output: new Uint8Array() }],
    ["missing output", { readError: new Error("private filesystem detail") }],
  ] as const)("cleans up and returns a safe error after %s", async (_label, options) => {
    const run = harness(options);

    await expect(exportAccountState(request, run.deps)).rejects.toMatchObject({
      code: "BOOTSTRAP_FAILED",
    });
    expect(run.removed).toEqual([run.tempDirectory]);
  });

  it("rejects browser-supplied fixed fields before creating temporary files", async () => {
    const run = harness();
    await expect(
      exportAccountState({ ...request, origin: "https://evil.example" } as BootstrapRequest, run.deps),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect(run.writes).toEqual([]);
    expect(run.spawns).toEqual([]);
    expect(run.removed).toEqual([]);
  });
});
