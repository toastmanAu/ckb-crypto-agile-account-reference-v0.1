/**
 * Publishes this repository's release ELFs as immutable CKB code cells.
 *
 * Safety model:
 *
 * - Dry run is the default. Nothing touches the network without `--broadcast`.
 * - Every artifact is data-hash verified against `deploy/reference-deployments.json`
 *   before a transaction is built. A code cell cannot be edited after publication.
 * - The signing key is read from `CKB_PRIVKEY` and never logged.
 * - One transaction per artifact, so a partial failure leaves unambiguous
 *   outpoints for what did land.
 * - After commitment each published cell is read back from the chain and its
 *   data hash re-verified before it is recorded.
 *
 * Usage:
 *
 *   npm run plan                        # phased P-256 selection, no network
 *   npm run plan -- --all               # all four artifacts
 *   CKB_PRIVKEY=0x... npm run deploy -- --broadcast
 *   CKB_PRIVKEY=0x... npm run deploy -- --broadcast --only verifier_p256
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ccc } from "@ckb-ccc/core";

import { SECP256K1_LOCK_ARGS_LENGTH } from "./artifacts.js";
import {
  buildDeploymentManifest,
  parseDeploymentArgs,
  type DeployedRecord,
} from "./deployment.js";
import { PlannedCell, buildDeploymentPlan, formatCkb } from "./plan.js";

/** Pool minimum is 1000 shannons/KW; 1200 leaves a margin for size drift. */
const FEE_RATE = 1200n;

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function printPlan(cells: PlannedCell[], total: bigint): void {
  console.log("Deployment plan (immutable code cells, hash_type data2)\n");
  for (const cell of cells) {
    console.log(`  ${cell.name}`);
    console.log(`    path      ${cell.path}`);
    console.log(`    bytes     ${cell.data.length.toLocaleString("en-US")}`);
    console.log(`    data hash ${cell.dataHash}`);
    console.log(`    capacity  ${formatCkb(cell.capacityShannons)}`);
  }
  console.log(`\n  TOTAL capacity ${formatCkb(total)} across ${cells.length} cells`);
  console.log("  (plus transaction fees, one transaction per cell)\n");
}

async function publishCell(
  signer: ccc.SignerCkbPrivateKey,
  cell: PlannedCell,
): Promise<DeployedRecord> {
  const lock = (await signer.getRecommendedAddressObj()).script;

  const tx = ccc.Transaction.from({
    outputs: [{ lock, capacity: cell.capacityShannons }],
    outputsData: [ccc.hexFrom(cell.data)],
  });

  // Inputs first, then fee. SignerCkbPrivateKey.prepareTransaction installs its
  // own 65-byte lock placeholder inside completeFeeBy, so a manual witness pad
  // here would be overwritten and is deliberately omitted.
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, FEE_RATE);

  const txHash = await signer.sendTransaction(tx);
  console.log(`    submitted ${txHash}`);
  await signer.client.waitTransaction(txHash, 0, 300_000);

  // Read the published cell back. A code cell is referenced by its data hash;
  // recording an outpoint without confirming what actually landed there would
  // publish a reference nothing can resolve.
  const published = await signer.client.getCellLive({ txHash, index: 0 }, true);
  if (!published) {
    throw new Error(`published cell ${txHash}:0 not found after commitment`);
  }
  const onChainHash = ccc.hashCkb(ccc.bytesFrom(published.outputData));
  if (onChainHash !== cell.dataHash) {
    throw new Error(
      `on-chain data hash for ${cell.name} is ${onChainHash}, expected ${cell.dataHash}`,
    );
  }
  console.log(`    verified  on-chain data hash matches ${cell.dataHash}`);

  return {
    name: cell.name,
    dataHash: cell.dataHash,
    hashType: "data2",
    txHash,
    index: 0,
    capacityShannons: cell.capacityShannons.toString(),
  };
}

async function main(): Promise<void> {
  const { broadcast, selection } = parseDeploymentArgs(process.argv.slice(2));
  const plan = buildDeploymentPlan(repoRoot, selection, SECP256K1_LOCK_ARGS_LENGTH);
  printPlan(plan.cells, plan.totalCapacityShannons);

  if (!broadcast) {
    console.log("Dry run. Re-run with --broadcast and CKB_PRIVKEY set to publish.");
    return;
  }

  const privateKey = process.env.CKB_PRIVKEY;
  if (!privateKey) {
    throw new Error("CKB_PRIVKEY is not set; refusing to broadcast");
  }

  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, privateKey);
  const address = await signer.getRecommendedAddress();
  const balance = await signer.getBalance();

  console.log(`Deploying from ${address}`);
  console.log(`Balance ${formatCkb(balance)}\n`);

  if (balance < plan.totalCapacityShannons) {
    throw new Error(
      `insufficient balance: need at least ${formatCkb(plan.totalCapacityShannons)} ` +
        `plus fees, have ${formatCkb(balance)}`,
    );
  }

  const records: DeployedRecord[] = [];
  for (const cell of plan.cells) {
    console.log(`  publishing ${cell.name} (${formatCkb(cell.capacityShannons)})`);
    records.push(await publishCell(signer, cell));
  }

  const outputPath = resolve(repoRoot, "deploy/testnet-deployments.json");
  const existing: unknown = existsSync(outputPath)
    ? JSON.parse(readFileSync(outputPath, "utf8"))
    : undefined;
  const manifest = buildDeploymentManifest(existing, records);
  writeFileSync(
    outputPath,
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  console.log(`\nWrote ${outputPath}`);
}

main().catch((error) => {
  console.error(`\nDeployment failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
