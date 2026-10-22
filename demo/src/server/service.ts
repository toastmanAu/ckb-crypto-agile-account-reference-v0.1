import { hashCkb } from "@ckb-ccc/core";

import { INITIAL_ASSET, CLIENT_ORIGIN, RP_ID, SHANNONS_PER_CKB } from "../shared/constants.js";
import { hexFromBytes } from "../shared/bytes.js";
import {
  AccountManifestSchema,
  BootstrapRequestSchema,
  DeploymentManifestSchema,
  type AccountManifest,
  type BootstrapRequest,
  type DemoStatus,
  type DeploymentManifest,
} from "../shared/schemas.js";
import { ApiError } from "./errors.js";

const ACCOUNT_LOCK_ARGS_LENGTH = 33;
const TYPE_ID_ARGS_LENGTH = 32;
const BOOTSTRAP_FEE_RESERVE = SHANNONS_PER_CKB;

export interface LiveStateCell {
  outputData: string;
}

export interface DemoServiceDeps {
  deployment: unknown;
  funderAddress(): Promise<string>;
  funderBalanceShannons(): Promise<bigint>;
  readAccountManifest(): unknown;
  getDeploymentCell(outPoint: { txHash: string; index: number }): Promise<LiveStateCell | null>;
  getStateCell(outPoint: AccountManifest["state_out_point"]): Promise<LiveStateCell | null>;
  exportState(request: BootstrapRequest): Promise<Uint8Array>;
  bootstrap(stateData: Uint8Array): Promise<AccountManifest>;
}

export interface DemoService {
  status(): Promise<DemoStatus>;
  account(): Promise<AccountManifest | null>;
  bootstrap(request: BootstrapRequest): Promise<AccountManifest>;
}

function accountStateCapacity(stateLength: number): bigint {
  const occupiedBytes =
    8 +
    (32 + 1 + ACCOUNT_LOCK_ARGS_LENGTH) +
    (32 + 1 + TYPE_ID_ARGS_LENGTH) +
    stateLength;
  return BigInt(occupiedBytes) * SHANNONS_PER_CKB;
}

function parseAccount(value: unknown, deployment: DeploymentManifest): AccountManifest | null {
  if (value === null) return null;
  const parsed = AccountManifestSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.account_lock.code_hash !== deployment.artifacts.account_lock.dataHash
  ) {
    throw new ApiError(
      "ACCOUNT_MISMATCH",
      409,
      "Recorded account does not match this testnet deployment",
    );
  }
  return parsed.data;
}

function isConfirmationTimeout(error: unknown): boolean {
  return error instanceof Error && error.name === "ErrorClientWaitTransactionTimeout";
}

export function createDemoService(deps: DemoServiceDeps): DemoService {
  const deploymentResult = DeploymentManifestSchema.safeParse(deps.deployment);
  if (!deploymentResult.success) {
    throw new ApiError("DEPLOYMENT_INVALID", 500, "Testnet deployment is invalid");
  }
  const deployment = deploymentResult.data;
  let deploymentVerification: Promise<void> | undefined;
  let active:
    | { publicKey: string; promise: Promise<AccountManifest> }
    | undefined;

  const account = async (): Promise<AccountManifest | null> =>
    parseAccount(deps.readAccountManifest(), deployment);

  const verifyDeployment = (): Promise<void> => {
    if (deploymentVerification !== undefined) return deploymentVerification;
    const verification = (async () => {
      for (const artifact of Object.values(deployment.artifacts)) {
        const cell = await deps.getDeploymentCell({
          txHash: artifact.txHash,
          index: artifact.index,
        });
        if (cell === null || hashCkb(cell.outputData) !== artifact.dataHash) {
          throw new ApiError(
            "DEPLOYMENT_INVALID",
            500,
            "Published testnet code cells could not be verified",
          );
        }
      }
    })();
    deploymentVerification = verification.catch((error: unknown) => {
      deploymentVerification = undefined;
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        "DEPLOYMENT_INVALID",
        500,
        "Published testnet code cells could not be verified",
      );
    });
    return deploymentVerification;
  };

  const bootstrapOnce = async (request: BootstrapRequest): Promise<AccountManifest> => {
    await verifyDeployment();
    let stateData: Uint8Array;
    try {
      stateData = await deps.exportState(request);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError("BOOTSTRAP_FAILED", 500, "Account state export failed");
    }

    const existing = await account();
    if (existing !== null) {
      const live = await deps.getStateCell(existing.state_out_point);
      if (
        live === null ||
        existing.state_bytes !== stateData.length ||
        live.outputData.toLowerCase() !== hexFromBytes(stateData)
      ) {
        throw new ApiError(
          "ACCOUNT_MISMATCH",
          409,
          "Existing account does not match this passkey",
        );
      }
      return existing;
    }

    const required =
      accountStateCapacity(stateData.length) + INITIAL_ASSET + BOOTSTRAP_FEE_RESERVE;
    if ((await deps.funderBalanceShannons()) < required) {
      throw new ApiError(
        "INSUFFICIENT_BALANCE",
        409,
        "Backend funder balance is insufficient for account creation",
      );
    }

    try {
      const created = await deps.bootstrap(stateData);
      const parsed = parseAccount(created, deployment);
      if (parsed === null) {
        throw new ApiError("BOOTSTRAP_FAILED", 500, "Account creation returned no manifest");
      }
      return parsed;
    } catch (error) {
      if (isConfirmationTimeout(error)) {
        throw new ApiError(
          "CONFIRMATION_TIMEOUT",
          504,
          "Account transaction was submitted but confirmation timed out",
        );
      }
      if (error instanceof ApiError) throw error;
      throw new ApiError("BOOTSTRAP_FAILED", 500, "Account creation failed");
    }
  };

  return {
    async status() {
      await verifyDeployment();
      const [funderAddress, funderBalance, currentAccount] = await Promise.all([
        deps.funderAddress(),
        deps.funderBalanceShannons(),
        account(),
      ]);
      return {
        schemaVersion: 1,
        network: "testnet",
        origin: CLIENT_ORIGIN,
        rpId: RP_ID,
        deploymentVerified: true,
        deployment,
        funderAddress,
        funderBalanceShannons: funderBalance.toString(),
        account: currentAccount,
      };
    },
    account,
    bootstrap(requestValue) {
      const requestResult = BootstrapRequestSchema.safeParse(requestValue);
      if (!requestResult.success) {
        return Promise.reject(
          new ApiError("INVALID_REQUEST", 400, "Invalid account bootstrap request"),
        );
      }
      const request = requestResult.data;
      if (active !== undefined) {
        if (active.publicKey !== request.publicKey) {
          return Promise.reject(
            new ApiError(
              "ACCOUNT_MISMATCH",
              409,
              "A different account creation is already in progress",
            ),
          );
        }
        return active.promise;
      }

      const promise = bootstrapOnce(request).finally(() => {
        if (active?.promise === promise) active = undefined;
      });
      active = { publicKey: request.publicKey, promise };
      return promise;
    },
  };
}
