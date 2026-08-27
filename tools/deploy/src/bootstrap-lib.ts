import {
  closeSync,
  fsyncSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { ccc } from "@ckb-ccc/core";

import { accountLockScript, assertCreationConsistency, typeIdScript } from "./account.js";
import { cellCapacityShannons } from "./artifacts.js";

export const BOOTSTRAP_FEE_RATE = 1200n;
export const DEFAULT_ASSET_CAPACITY_CKB = 200n;
export const SHANNONS_PER_CKB = 100_000_000n;

const ACCOUNT_LOCK_ARGS_LENGTH = 33;
const TYPE_ID_ARGS_LENGTH = 32;
const PLACEHOLDER_32 = `0x${"00".repeat(32)}`;

export interface BootstrapOptions {
  stateData: Uint8Array;
  assetCapacityCkb: bigint;
}

export interface TestnetAccountManifest {
  schema_version: 1;
  network: "testnet";
  account_id: string;
  account_lock: {
    code_hash: string;
    hash_type: "data2";
    args: string;
  };
  type_id_args: string;
  state_out_point: { tx_hash: string; index: 0 };
  asset_out_point: { tx_hash: string; index: 1 };
  state_bytes: number;
}

export interface BootstrapTransactionOps {
  completeInputs(tx: ccc.Transaction, signer: ccc.Signer): Promise<void>;
  completeFee(tx: ccc.Transaction, signer: ccc.Signer, feeRate: bigint): Promise<void>;
}

export interface BootstrapDeps {
  repoRoot: string;
  client: Pick<ccc.Client, "waitTransaction">;
  signer: ccc.Signer;
  readJson(path: string): unknown;
  writeJsonAtomic(path: string, value: unknown): void;
  transactionOps?: BootstrapTransactionOps;
}

const defaultTransactionOps: BootstrapTransactionOps = {
  async completeInputs(tx, signer) {
    await tx.completeInputsByCapacity(signer);
  },
  async completeFee(tx, signer, feeRate) {
    await tx.completeFeeBy(signer, feeRate);
  },
};

function accountLockCodeHash(manifest: unknown): string {
  if (typeof manifest !== "object" || manifest === null) {
    throw new Error("testnet deployment manifest is missing");
  }
  const root = manifest as Record<string, unknown>;
  const artifacts = root.artifacts as Record<string, unknown> | undefined;
  const accountLock = artifacts?.account_lock as Record<string, unknown> | undefined;
  const dataHash = accountLock?.dataHash;
  if (
    root.schema_version !== 1 ||
    root.network !== "testnet" ||
    root.published !== true ||
    root.hash_type !== "data2" ||
    accountLock?.hashType !== "data2" ||
    typeof dataHash !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(dataHash)
  ) {
    throw new Error("testnet deployment manifest has no verified data2 AccountLock");
  }
  return dataHash;
}

function validateOptions(options: BootstrapOptions): {
  stateCapacity: bigint;
  assetCapacity: bigint;
} {
  if (!(options.stateData instanceof Uint8Array) || options.stateData.length === 0) {
    throw new Error("AccountStateV1 state data is required");
  }
  if (options.assetCapacityCkb <= 0n) {
    throw new Error("asset capacity must be a positive whole number of CKB");
  }

  const stateCapacity = cellCapacityShannons({
    lockArgsLength: ACCOUNT_LOCK_ARGS_LENGTH,
    typeArgsLength: TYPE_ID_ARGS_LENGTH,
    dataLength: options.stateData.length,
  });
  const assetCapacity = options.assetCapacityCkb * SHANNONS_PER_CKB;
  const minimumAsset = cellCapacityShannons({
    lockArgsLength: ACCOUNT_LOCK_ARGS_LENGTH,
    typeArgsLength: null,
    dataLength: 0,
  });
  if (assetCapacity < minimumAsset) {
    throw new Error(
      `asset capacity is below the ${minimumAsset} shannon AccountLock cell minimum`,
    );
  }
  return { stateCapacity, assetCapacity };
}

export async function bootstrapAccount(
  options: BootstrapOptions,
  deps: BootstrapDeps,
): Promise<TestnetAccountManifest> {
  const { stateCapacity, assetCapacity } = validateOptions(options);
  const accountPath = resolve(deps.repoRoot, "deploy/testnet-account.json");
  if (deps.readJson(accountPath) !== null) {
    throw new Error("deploy/testnet-account.json already exists; refusing to replace it");
  }

  const deploymentPath = resolve(deps.repoRoot, "deploy/testnet-deployments.json");
  const codeHash = accountLockCodeHash(deps.readJson(deploymentPath));
  const stateHex = ccc.hexFrom(options.stateData);
  const tx = ccc.Transaction.from({
    outputs: [
      {
        lock: accountLockScript(codeHash, PLACEHOLDER_32),
        type: typeIdScript(PLACEHOLDER_32),
        capacity: stateCapacity,
      },
      {
        lock: accountLockScript(codeHash, PLACEHOLDER_32),
        capacity: assetCapacity,
      },
    ],
    outputsData: [stateHex, "0x"],
  });

  const transactionOps = deps.transactionOps ?? defaultTransactionOps;
  await transactionOps.completeInputs(tx, deps.signer);
  if (tx.inputs.length === 0) {
    throw new Error("input collection returned no cells");
  }

  const typeIdArgs = ccc.hashTypeId(tx.inputs[0], 0);
  tx.outputs[0].type = typeIdScript(typeIdArgs);
  const accountId = tx.outputs[0].type.hash();
  tx.outputs[0].lock = accountLockScript(codeHash, accountId);
  tx.outputs[1].lock = accountLockScript(codeHash, accountId);

  await transactionOps.completeFee(tx, deps.signer, BOOTSTRAP_FEE_RATE);
  assertCreationConsistency(tx, codeHash, stateHex);

  const txHash = await deps.signer.sendTransaction(tx);
  await deps.client.waitTransaction(txHash, 0, 300_000);

  const manifest: TestnetAccountManifest = {
    schema_version: 1,
    network: "testnet",
    account_id: accountId,
    account_lock: {
      code_hash: codeHash,
      hash_type: "data2",
      args: tx.outputs[0].lock.args,
    },
    type_id_args: typeIdArgs,
    state_out_point: { tx_hash: txHash, index: 0 },
    asset_out_point: { tx_hash: txHash, index: 1 },
    state_bytes: options.stateData.length,
  };
  deps.writeJsonAtomic(accountPath, manifest);
  return manifest;
}

export function writeJsonAtomicFile(path: string, value: unknown): void {
  const directory = dirname(path);
  const temporary = resolve(
    directory,
    `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
  } catch (error) {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created or may already be renamed.
    }
    throw error;
  }
}
