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
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ccc } from "@ckb-ccc/core";

import { cellCapacityShannons, readLocalArtifactIdentities } from "./artifacts.js";
import {
  bootstrapAccount,
  writeJsonAtomicFile,
} from "./bootstrap-lib.js";
import { formatCkb } from "./plan.js";

const SHANNONS_PER_CKB = 100_000_000n;
const ACCOUNT_LOCK_ARGS_LENGTH = 33;
const TYPE_ID_ARGS_LENGTH = 32;

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

function readJsonOrNull(path: string): unknown {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const stateData = readFileSync(resolve(options.statePath));
  if (stateData.length === 0) {
    throw new Error(`${options.statePath} is empty`);
  }

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
  const manifest = await bootstrapAccount(
    { stateData, assetCapacityCkb: options.assetCapacityCkb },
    {
      repoRoot,
      client,
      signer,
      readJson: readJsonOrNull,
      writeJsonAtomic: writeJsonAtomicFile,
    },
  );

  console.log(`  account id ${manifest.account_id}`);
  console.log(`  lock args  ${manifest.account_lock.args}`);
  console.log(`  committed  ${manifest.state_out_point.tx_hash}`);
  console.log(`\nWrote ${resolve(repoRoot, "deploy/testnet-account.json")}`);
}

main().catch((error) => {
  console.error(
    `\nAccount creation failed: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
