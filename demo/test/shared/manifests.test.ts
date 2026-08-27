import { ccc } from "@ckb-ccc/core";
import { describe, expect, it } from "vitest";

import vector from "../../../vectors/frontend-v1.json";
import {
  TYPE_ID_CODE_HASH,
  validateAccount,
  validateDeployment,
} from "../../src/shared/manifests.js";
import type {
  AccountManifest,
  DeploymentManifest,
} from "../../src/shared/schemas.js";

const deployment: DeploymentManifest = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe",
      hashType: "data2",
      txHash: `0x${"11".repeat(32)}`,
      index: 0,
      capacityShannons: "3350900000000",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: "0x376a3e1bfefc57d63cff2e5d022283800fb6b5f014b5edac4be573d58a7b124a",
      hashType: "data2",
      txHash: `0x${"22".repeat(32)}`,
      index: 0,
      capacityShannons: "6218100000000",
    },
  },
};

function accountFixture(): AccountManifest {
  const typeIdArgs = `0x${"44".repeat(32)}`;
  const accountId = ccc.Script.from({
    codeHash: TYPE_ID_CODE_HASH,
    hashType: "type",
    args: typeIdArgs,
  }).hash();
  return {
    schema_version: 1,
    network: "testnet",
    account_id: accountId,
    account_lock: {
      code_hash: deployment.artifacts.account_lock.dataHash,
      hash_type: "data2",
      args: `0x01${accountId.slice(2)}`,
    },
    type_id_args: typeIdArgs,
    state_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 0 },
    asset_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 1 },
    state_bytes: (vector.state.length - 2) / 2,
  };
}

describe("verified public manifests", () => {
  it("derives data2 code scripts and deterministic code deps", () => {
    const verified = validateDeployment(deployment);

    expect(verified.accountLockCode.codeHash).toBe(deployment.artifacts.account_lock.dataHash);
    expect(verified.accountLockCode.hashType).toBe("data2");
    expect(verified.accountLockDep.outPoint.txHash).toBe(
      deployment.artifacts.account_lock.txHash,
    );
    expect(verified.accountLockDep.depType).toBe("code");
    expect(verified.verifierP256Dep.outPoint.txHash).toBe(
      deployment.artifacts.verifier_p256.txHash,
    );
  });

  it("binds AccountLock args and the Type ID script hash to the account ID", () => {
    const verified = validateAccount(accountFixture(), validateDeployment(deployment));

    expect(verified.accountLock.args).toBe(`0x01${verified.manifest.account_id.slice(2)}`);
    expect(verified.stateType.codeHash).toBe(TYPE_ID_CODE_HASH);
    expect(verified.stateType.hash()).toBe(verified.manifest.account_id);
  });

  it("rejects a code hash not recorded as the deployed data hash", () => {
    const account = accountFixture();
    account.account_lock.code_hash = `0x${"99".repeat(32)}`;
    account.account_lock.args = `0x01${account.account_id.slice(2)}`;

    expect(() => validateAccount(account, validateDeployment(deployment))).toThrow(
      /deployment/i,
    );
  });

  it("rejects invalid state/asset indexes and Type ID account hashes", () => {
    const wrongIndex = accountFixture();
    wrongIndex.state_out_point.index = 2;
    expect(() => validateAccount(wrongIndex, validateDeployment(deployment))).toThrow(
      /outpoint/i,
    );

    const wrongTypeId = accountFixture();
    wrongTypeId.account_id = `0x${"88".repeat(32)}`;
    wrongTypeId.account_lock.args = `0x01${wrongTypeId.account_id.slice(2)}`;
    expect(() => validateAccount(wrongTypeId, validateDeployment(deployment))).toThrow(
      /Type ID/i,
    );
  });
});
