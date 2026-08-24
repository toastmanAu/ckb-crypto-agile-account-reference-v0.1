import { CellDep, Script } from "@ckb-ccc/core";

import {
  AccountManifestSchema,
  DeploymentManifestSchema,
  type AccountManifest,
  type DeploymentManifest,
} from "./schemas.js";

export const TYPE_ID_CODE_HASH =
  "0x00000000000000000000000000000000000000000000000000545950455f4944";

export interface VerifiedDeployment {
  manifest: DeploymentManifest;
  accountLockCode: Script;
  verifierP256Code: Script;
  accountLockDep: CellDep;
  verifierP256Dep: CellDep;
}

export interface VerifiedAccount {
  manifest: AccountManifest;
  deployment: VerifiedDeployment;
  accountLock: Script;
  stateType: Script;
  stateDep: CellDep;
}

function invalidManifest(label: string): TypeError {
  return new TypeError(`${label} manifest is invalid`);
}

export function validateDeployment(value: unknown): VerifiedDeployment {
  const result = DeploymentManifestSchema.safeParse(value);
  if (!result.success) {
    throw invalidManifest("Deployment");
  }
  const manifest = result.data;
  const accountLockCode = Script.from({
    codeHash: manifest.artifacts.account_lock.dataHash,
    hashType: manifest.artifacts.account_lock.hashType,
    args: "0x",
  });
  const verifierP256Code = Script.from({
    codeHash: manifest.artifacts.verifier_p256.dataHash,
    hashType: manifest.artifacts.verifier_p256.hashType,
    args: "0x",
  });
  const accountLockDep = CellDep.from({
    outPoint: {
      txHash: manifest.artifacts.account_lock.txHash,
      index: manifest.artifacts.account_lock.index,
    },
    depType: "code",
  });
  const verifierP256Dep = CellDep.from({
    outPoint: {
      txHash: manifest.artifacts.verifier_p256.txHash,
      index: manifest.artifacts.verifier_p256.index,
    },
    depType: "code",
  });
  return {
    manifest,
    accountLockCode,
    verifierP256Code,
    accountLockDep,
    verifierP256Dep,
  };
}

export function validateAccount(
  value: unknown,
  deployment: VerifiedDeployment,
): VerifiedAccount {
  const result = AccountManifestSchema.safeParse(value);
  if (!result.success) {
    throw invalidManifest("Account");
  }
  const manifest = result.data;
  if (manifest.account_lock.code_hash !== deployment.accountLockCode.codeHash) {
    throw new TypeError("Account manifest does not match the verified deployment");
  }
  if (
    manifest.state_out_point.index !== 0 ||
    manifest.asset_out_point.index !== 1 ||
    manifest.state_out_point.tx_hash !== manifest.asset_out_point.tx_hash
  ) {
    throw new TypeError("Account manifest has invalid bootstrap outpoints");
  }

  const accountLock = Script.from({
    codeHash: manifest.account_lock.code_hash,
    hashType: manifest.account_lock.hash_type,
    args: manifest.account_lock.args,
  });
  const expectedArgs = `0x01${manifest.account_id.slice(2)}`;
  if (accountLock.args !== expectedArgs) {
    throw new TypeError("AccountLock args do not bind the account ID");
  }
  const stateType = Script.from({
    codeHash: TYPE_ID_CODE_HASH,
    hashType: "type",
    args: manifest.type_id_args,
  });
  if (stateType.hash() !== manifest.account_id) {
    throw new TypeError("Type ID script hash does not match the account ID");
  }
  const stateDep = CellDep.from({
    outPoint: {
      txHash: manifest.state_out_point.tx_hash,
      index: manifest.state_out_point.index,
    },
    depType: "code",
  });
  return { manifest, deployment, accountLock, stateType, stateDep };
}
