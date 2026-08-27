import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ccc } from "@ckb-ccc/core";

import {
  bootstrapAccount,
  writeJsonAtomicFile,
} from "../../../tools/deploy/src/bootstrap-lib.js";
import { INITIAL_ASSET, SHANNONS_PER_CKB } from "../shared/constants.js";
import {
  DeploymentManifestSchema,
  type AccountManifest,
} from "../shared/schemas.js";
import { loadServerConfig } from "./config.js";
import { ApiError, toSafeErrorBody } from "./errors.js";
import { createHttpServer } from "./http.js";
import { createDemoService } from "./service.js";
import { createExporterDeps, exportAccountState } from "./state-exporter.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function readJsonOrNull(path: string): unknown {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main(): Promise<void> {
  const config = loadServerConfig(process.env);
  const deploymentPath = resolve(repoRoot, "deploy/testnet-deployments.json");
  const deploymentResult = DeploymentManifestSchema.safeParse(readJsonOrNull(deploymentPath));
  if (!deploymentResult.success) {
    throw new ApiError("DEPLOYMENT_INVALID", 500, "Testnet deployment is invalid");
  }
  const deployment = deploymentResult.data;
  const accountPath = resolve(repoRoot, "deploy/testnet-account.json");
  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, config.privateKey);
  const exporterDeps = createExporterDeps(repoRoot, deployment);

  const service = createDemoService({
    deployment,
    funderAddress: () => signer.getRecommendedAddress(),
    funderBalanceShannons: () => signer.getBalance(),
    readAccountManifest: () => readJsonOrNull(accountPath),
    async getDeploymentCell(outPoint) {
      const cell = await client.getCellLive(outPoint, true);
      return cell === undefined ? null : { outputData: cell.outputData };
    },
    async getStateCell(outPoint) {
      const cell = await client.getCellLive(
        { txHash: outPoint.tx_hash, index: outPoint.index },
        true,
      );
      return cell === undefined ? null : { outputData: cell.outputData };
    },
    exportState: (request) => exportAccountState(request, exporterDeps),
    async bootstrap(stateData): Promise<AccountManifest> {
      return bootstrapAccount(
        { stateData, assetCapacityCkb: INITIAL_ASSET / SHANNONS_PER_CKB },
        {
          repoRoot,
          client,
          signer,
          readJson: readJsonOrNull,
          writeJsonAtomic: writeJsonAtomicFile,
        },
      );
    },
  });
  const [address, balance] = await Promise.all([
    signer.getRecommendedAddress(),
    signer.getBalance(),
  ]);
  const server = createHttpServer(service);
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, resolvePromise);
  });

  console.log(`CKB passkey demo API listening on http://${config.host}:${config.port}`);
  console.log(`Network ${config.network}`);
  console.log(`Funder ${address}`);
  console.log(`Balance ${balance.toString()} shannons`);
}

void main().catch((error: unknown) => {
  const body = toSafeErrorBody(error);
  console.error(`${body.error.code}: ${body.error.message}`);
  process.exitCode = 1;
});
