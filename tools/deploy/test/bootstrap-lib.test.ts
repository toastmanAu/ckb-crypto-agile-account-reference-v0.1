import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ccc } from "@ckb-ccc/core";
import { describe, expect, it } from "vitest";

import {
  bootstrapAccount,
  writeJsonAtomicFile,
  type BootstrapDeps,
} from "../src/bootstrap-lib.js";

const ACCOUNT_LOCK_CODE_HASH =
  "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe";
const TX_HASH = `0x${"77".repeat(32)}`;
const INPUT_TX_HASH = `0x${"aa".repeat(32)}`;
const FUNDER_LOCK = ccc.Script.from({
  codeHash: `0x${"99".repeat(32)}`,
  hashType: "type",
  args: `0x${"bb".repeat(20)}`,
});

const deployment = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: ACCOUNT_LOCK_CODE_HASH,
      hashType: "data2",
      txHash: `0x${"55".repeat(32)}`,
      index: 0,
      capacityShannons: "3350900000000",
    },
  },
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function harness(options: { wait?: Promise<void>; existingAccount?: unknown } = {}) {
  const events: string[] = [];
  const writes: Array<{ path: string; value: unknown }> = [];
  let sent: ccc.Transaction | undefined;

  const signer = {
    async sendTransaction(tx: ccc.Transaction) {
      events.push("send");
      sent = tx;
      return TX_HASH;
    },
  } as unknown as ccc.Signer;
  const client = {
    async waitTransaction(txHash: string, confirmations: number, timeout: number) {
      events.push(`wait:${txHash}:${confirmations}:${timeout}`);
      await options.wait;
    },
  } as Pick<ccc.Client, "waitTransaction">;

  const deps: BootstrapDeps = {
    repoRoot: "/repo",
    client,
    signer,
    readJson(path) {
      if (path.endsWith("testnet-deployments.json")) return deployment;
      if (path.endsWith("testnet-account.json")) return options.existingAccount ?? null;
      throw new Error(`unexpected read ${path}`);
    },
    writeJsonAtomic(path, value) {
      events.push("write");
      writes.push({ path, value });
    },
    transactionOps: {
      async completeInputs(tx) {
        events.push("inputs");
        tx.inputs.push(
          ccc.CellInput.from({
            previousOutput: { txHash: INPUT_TX_HASH, index: 0 },
            since: 0,
          }),
        );
      },
      async completeFee(tx, _signer, feeRate) {
        events.push(`fee:${feeRate}`);
        tx.outputs.push(
          ccc.CellOutput.from({ lock: FUNDER_LOCK, capacity: 1_000_000_000n }),
        );
        tx.outputsData.push("0x");
      },
    },
  };

  return { deps, events, writes, sent: () => sent };
}

describe("bootstrapAccount", () => {
  it("rejects missing state bytes and an under-capacity asset before collection", async () => {
    const empty = harness();
    await expect(
      bootstrapAccount({ stateData: new Uint8Array(), assetCapacityCkb: 200n }, empty.deps),
    ).rejects.toThrow(/state data/i);
    expect(empty.events).toEqual([]);

    const occupied = harness();
    await expect(
      bootstrapAccount(
        { stateData: Uint8Array.of(1), assetCapacityCkb: 73n },
        occupied.deps,
      ),
    ).rejects.toThrow(/minimum/i);
    expect(occupied.events).toEqual([]);
  });

  it("builds the 200 CKB account cells and patches identity after input collection", async () => {
    const run = harness();
    const stateData = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);

    const manifest = await bootstrapAccount(
      { stateData, assetCapacityCkb: 200n },
      run.deps,
    );

    const tx = run.sent();
    expect(tx).toBeDefined();
    expect(tx!.outputs).toHaveLength(3);
    expect(tx!.outputs[1].capacity).toBe(20_000_000_000n);
    expect(tx!.outputs[0].lock.hashType).toBe("data2");
    expect(tx!.outputs[0].lock.args).toBe(tx!.outputs[1].lock.args);
    expect(tx!.outputs[2].lock.codeHash).toBe(FUNDER_LOCK.codeHash);
    expect(tx!.outputsData).toEqual(["0xdeadbeef", "0x", "0x"]);
    expect(manifest.account_id).toBe(tx!.outputs[0].type!.hash());
    expect(manifest.account_lock.args).toBe(tx!.outputs[0].lock.args);
    expect(manifest.type_id_args).toBe(ccc.hashTypeId(tx!.inputs[0], 0));
    expect(manifest.state_out_point).toEqual({ tx_hash: TX_HASH, index: 0 });
    expect(manifest.asset_out_point).toEqual({ tx_hash: TX_HASH, index: 1 });
    expect(manifest.state_bytes).toBe(4);
    expect(run.events).toEqual([
      "inputs",
      "fee:1200",
      "send",
      `wait:${TX_HASH}:0:300000`,
      "write",
    ]);
  });

  it("does not publish the manifest until commitment completes", async () => {
    const commitment = deferred();
    const run = harness({ wait: commitment.promise });

    const pending = bootstrapAccount(
      { stateData: Uint8Array.of(1), assetCapacityCkb: 200n },
      run.deps,
    );
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(run.writes).toHaveLength(0);

    commitment.resolve();
    await pending;
    expect(run.writes).toHaveLength(1);
    expect(run.writes[0].path).toBe("/repo/deploy/testnet-account.json");
  });

  it("refuses to replace an existing account manifest", async () => {
    const run = harness({ existingAccount: { account_id: `0x${"12".repeat(32)}` } });
    await expect(
      bootstrapAccount(
        { stateData: Uint8Array.of(1), assetCapacityCkb: 200n },
        run.deps,
      ),
    ).rejects.toThrow(/already exists/i);
    expect(run.events).toEqual([]);
  });
});

describe("writeJsonAtomicFile", () => {
  it("atomically writes private JSON with a trailing newline", () => {
    const directory = mkdtempSync(join(tmpdir(), "ckb-account-bootstrap-"));
    const path = join(directory, "account.json");

    writeJsonAtomicFile(path, { safe: "public metadata" });

    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ safe: "public metadata" });
    expect(readFileSync(path, "utf8").endsWith("\n")).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});
