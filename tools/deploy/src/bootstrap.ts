/**
 * Creates a singleton AccountStateV1 cell and one funded asset cell.
 *
 * The state bytes are produced by the Rust exporter and consumed here as opaque
 * data — this tool never encodes AccountStateV1 itself:
 *
 *   cargo run -p ckb-account-host --example export_account_state -- \
 *     my-account.json /tmp/account-state.bin
 *
 * Usage:
 *
 *   npm run bootstrap -- --state /tmp/account-state.bin
 *   CKB_PRIVKEY=0x... npm run bootstrap -- --state /tmp/account-state.bin --broadcast
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ccc } from "@ckb-ccc/core";

import { cellCapacityShannons, readLocalArtifactIdentities } from "./artifacts.js";
import {
  accountLockScript,
  assertCreationConsistency,
  typeIdScript,
} from "./account.js";
import { formatCkb } from "./plan.js";

const FEE_RATE = 1200n;
const SHANNONS_PER_CKB = 100_000_000n;
const ACCOUNT_LOCK_ARGS_LENGTH = 33;
const TYPE_ID_ARGS_LENGTH = 32;

/** Same length as the real values, so patching them cannot shift capacity. */
const PLACEHOLDER_32 = `0x${"00".repeat(32)}`;

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

interface Options {
  statePath: string;
  assetCapacityCkb: bigint;
  broadcast: boolean;
}

function parseArgs(argv: string[]): Options {
  const value = (flag: string): string | undefined => {
    const index = argv.indexOf(flag);
    return index === -1 ? undefined : argv[index + 1];
  };

  const statePath = value("--state");
  if (!statePath) {
    throw new Error(
      "--state <path> is required; produce it with the export_account_state example",
    );
  }
  const assetRaw = value("--asset-capacity") ?? "200";
  if (!/^\d+$/.test(assetRaw)) {
    throw new Error(`--asset-capacity must be a whole number of CKB, got ${assetRaw}`);
  }

  return {
    statePath,
    assetCapacityCkb: BigInt(assetRaw),
    broadcast: argv.includes("--broadcast"),
  };
}

/**
 * Resolves the AccountLock code hash.
 *
 * A code cell's data hash is the same wherever it is published, so creation
 * does not require the cell to exist yet — no lock script runs when a cell is
 * created. It must exist before the account can ever be spent, so an
 * unpublished AccountLock is reported as a warning rather than accepted
 * silently.
 */
function resolveAccountLockCodeHash(): { codeHash: string; deployed: boolean } {
  const testnetPath = resolve(repoRoot, "deploy/testnet-deployments.json");
  if (existsSync(testnetPath)) {
    const manifest = JSON.parse(readFileSync(testnetPath, "utf8")) as {
      artifacts?: Record<string, { dataHash?: string }>;
    };
    const dataHash = manifest.artifacts?.account_lock?.dataHash;
    if (dataHash) {
      return { codeHash: dataHash, deployed: true };
    }
  }
  const identity = readLocalArtifactIdentities(repoRoot).account_lock;
  if (!identity) {
    throw new Error("no account_lock identity in deploy/reference-deployments.json");
  }
  return { codeHash: identity.dataHash, deployed: false };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const stateData = readFileSync(resolve(options.statePath));
  if (stateData.length === 0) {
    throw new Error(`${options.statePath} is empty`);
  }
  const stateHex = ccc.hexFrom(stateData);

  const { codeHash: accountLockCodeHash, deployed } = resolveAccountLockCodeHash();

  const stateCapacity = cellCapacityShannons({
    lockArgsLength: ACCOUNT_LOCK_ARGS_LENGTH,
    typeArgsLength: TYPE_ID_ARGS_LENGTH,
    dataLength: stateData.length,
  });
  const assetCapacity = options.assetCapacityCkb * SHANNONS_PER_CKB;
  const minimumAsset = cellCapacityShannons({
    lockArgsLength: ACCOUNT_LOCK_ARGS_LENGTH,
    typeArgsLength: null,
    dataLength: 0,
  });
  if (assetCapacity < minimumAsset) {
    throw new Error(
      `--asset-capacity ${formatCkb(assetCapacity)} is below the ${formatCkb(minimumAsset)} ` +
        `minimum for an AccountLock-locked cell`,
    );
  }

  console.log("Account creation plan\n");
  console.log(`  AccountLock code hash ${accountLockCodeHash}`);
  console.log(`  AccountLock published  ${deployed ? "yes" : "NOT YET"}`);
  console.log(`  state bytes            ${stateData.length}`);
  console.log(`  state cell capacity    ${formatCkb(stateCapacity)}`);
  console.log(`  asset cell capacity    ${formatCkb(assetCapacity)}`);
  console.log(`  total                  ${formatCkb(stateCapacity + assetCapacity)}\n`);

  if (!deployed) {
    console.log(
      "  WARNING: no deploy/testnet-deployments.json. Creation does not execute\n" +
        "  AccountLock, so this transaction would succeed, but the account cannot\n" +
        "  be spent until that code cell is published.\n",
    );
  }

  if (!options.broadcast) {
    console.log("Dry run. Re-run with --broadcast and CKB_PRIVKEY set to create.");
    return;
  }

  const privateKey = process.env.CKB_PRIVKEY;
  if (!privateKey) {
    throw new Error("CKB_PRIVKEY is not set; refusing to broadcast");
  }

  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, privateKey);
  console.log(`Creating from ${await signer.getRecommendedAddress()}\n`);

  // Both the Type ID args and the AccountLock args depend on the first input,
  // which does not exist until inputs are collected. Placeholders are the exact
  // length of the real values so patching cannot change any cell's size.
  const tx = ccc.Transaction.from({
    outputs: [
      {
        lock: accountLockScript(accountLockCodeHash, PLACEHOLDER_32),
        type: typeIdScript(PLACEHOLDER_32),
        capacity: stateCapacity,
      },
      {
        lock: accountLockScript(accountLockCodeHash, PLACEHOLDER_32),
        capacity: assetCapacity,
      },
    ],
    outputsData: [stateHex, "0x"],
  });

  await tx.completeInputsByCapacity(signer);

  const typeIdArgs = ccc.hashTypeId(tx.inputs[0], 0);
  tx.outputs[0].type = typeIdScript(typeIdArgs);
  const accountId = tx.outputs[0].type.hash();
  tx.outputs[0].lock = accountLockScript(accountLockCodeHash, accountId);
  tx.outputs[1].lock = accountLockScript(accountLockCodeHash, accountId);

  await tx.completeFeeBy(signer, FEE_RATE);

  // Runs last, so it sees the transaction exactly as it will be broadcast —
  // including any inputs or change outputs fee completion added.
  assertCreationConsistency(tx, accountLockCodeHash, stateHex);

  console.log(`  account id ${accountId}`);
  console.log(`  lock args  ${tx.outputs[0].lock.args}`);

  const txHash = await signer.sendTransaction(tx);
  console.log(`  submitted  ${txHash}`);
  await client.waitTransaction(txHash, 0, 300_000);
  console.log(`  committed`);

  const outputPath = resolve(repoRoot, "deploy/testnet-account.json");
  writeFileSync(
    outputPath,
    `${JSON.stringify(
      {
        schema_version: 1,
        network: "testnet",
        account_id: accountId,
        account_lock: {
          code_hash: accountLockCodeHash,
          hash_type: "data2",
          args: tx.outputs[0].lock.args,
        },
        type_id_args: typeIdArgs,
        state_out_point: { tx_hash: txHash, index: 0 },
        asset_out_point: { tx_hash: txHash, index: 1 },
        state_bytes: stateData.length,
      },
      null,
      2,
    )}\n`,
  );
  console.log(`\nWrote ${outputPath}`);
}

main().catch((error) => {
  console.error(
    `\nAccount creation failed: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
