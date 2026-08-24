import { ccc } from "@ckb-ccc/core";
import { describe, expect, it, vi } from "vitest";

import vector from "../../../vectors/frontend-v1.json";
import {
  confirmSpend,
  discoverAccountCells,
  finalizeSpend,
  prepareSpend,
  submitSpend,
  type SpendClient,
} from "../../src/client/chain.js";
import type { AssertionMaterial } from "../../src/client/passkey.js";
import {
  FEE_RATE,
  OP_SPEND,
  SHANNONS_PER_CKB,
  TRANSFER_CAPACITY,
} from "../../src/shared/constants.js";
import {
  TYPE_ID_CODE_HASH,
  validateAccount,
  validateDeployment,
} from "../../src/shared/manifests.js";
import {
  authorizationDigest,
  groupSighash,
} from "../../src/shared/protocol.js";
import type {
  AccountManifest,
  DeploymentManifest,
  PasskeyRecord,
} from "../../src/shared/schemas.js";

const FUNDER_ADDRESS =
  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvcantfhvtwtyzgd4ssn0gjnjhkkl9q9lswhlggn";
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
const passkey: PasskeyRecord = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey:
    "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  keyId: "0x924617c0c1ca9afcaee0d49ae6ad8b282836c33b9e976d26c7f8b2abb5401893",
  rpId: "localhost",
  origin: "http://localhost:5173",
  createdAt: "2026-08-24T00:00:00.000Z",
};

function fixtures() {
  const typeIdArgs = `0x${"44".repeat(32)}`;
  const accountId = ccc.Script.from({
    codeHash: TYPE_ID_CODE_HASH,
    hashType: "type",
    args: typeIdArgs,
  }).hash();
  const manifest: AccountManifest = {
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
  const verified = validateAccount(manifest, validateDeployment(deployment));
  const stateData = ccc.bytesFrom(vector.state);
  stateData.set(ccc.bytesFrom(passkey.keyId), 80);
  const state = ccc.Cell.from({
    outPoint: { txHash: manifest.state_out_point.tx_hash, index: 0 },
    cellOutput: {
      capacity: 177n * SHANNONS_PER_CKB,
      lock: verified.accountLock,
      type: verified.stateType,
    },
    outputData: ccc.hexFrom(stateData),
  });
  const asset = ccc.Cell.from({
    outPoint: { txHash: manifest.asset_out_point.tx_hash, index: 1 },
    cellOutput: { capacity: 200n * SHANNONS_PER_CKB, lock: verified.accountLock },
    outputData: "0x",
  });
  return { verified, state, asset };
}

function clientFor(
  cells: ccc.Cell[],
  state: ccc.Cell | null = fixtures().state,
  assetLive = true,
): SpendClient {
  return {
    addressPrefix: "ckt",
    getCellLive: vi.fn(async (outPoint: ccc.OutPointLike) => {
      const resolved = ccc.OutPoint.from(outPoint);
      if (resolved.index === 0n) return state ?? undefined;
      if (!assetLive) return undefined;
      return cells.find((cell) => cell.outPoint.eq(resolved));
    }),
    async *findCellsByLock() {
      for (const cell of cells) yield cell;
    },
    sendTransaction: vi.fn(),
    waitTransaction: vi.fn(),
  } as unknown as SpendClient;
}

describe("live AccountLock cell discovery", () => {
  it("resolves the exact live state and single type-less asset", async () => {
    const { verified, state, asset } = fixtures();
    await expect(discoverAccountCells(clientFor([state, asset], state), verified)).resolves.toEqual({
      state,
      asset,
    });
  });

  it("rejects a spent state and zero or multiple assets", async () => {
    const { verified, state, asset } = fixtures();
    await expect(discoverAccountCells(clientFor([asset], null), verified)).rejects.toThrow(
      /state/i,
    );
    await expect(discoverAccountCells(clientFor([state], state), verified)).rejects.toThrow(
      /one.*asset/i,
    );
    const second = ccc.Cell.from({
      outPoint: { txHash: `0x${"55".repeat(32)}`, index: 0 },
      cellOutput: asset.cellOutput,
      outputData: "0x",
    });
    await expect(
      discoverAccountCells(clientFor([state, asset, second], state), verified),
    ).rejects.toThrow(/one.*asset/i);
    await expect(
      discoverAccountCells(clientFor([state, asset], state, false), verified),
    ).rejects.toThrow(/spent or changed/i);
  });

  it("rejects typed asset candidates, foreign locks, and changed state data", async () => {
    const { verified, state, asset } = fixtures();
    const typed = ccc.Cell.from({
      outPoint: asset.outPoint,
      cellOutput: { ...asset.cellOutput, type: verified.stateType },
      outputData: "0x",
    });
    await expect(discoverAccountCells(clientFor([state, typed], state), verified)).rejects.toThrow(
      /typed/i,
    );

    const foreign = ccc.Cell.from({
      outPoint: asset.outPoint,
      cellOutput: {
        ...asset.cellOutput,
        lock: { ...verified.accountLock, args: `0x01${"99".repeat(32)}` },
      },
      outputData: "0x",
    });
    await expect(
      discoverAccountCells(clientFor([state, foreign], state), verified),
    ).rejects.toThrow(/lock/i);

    const changedState = ccc.Cell.from({ ...state, outputData: `${vector.state.slice(0, -2)}00` });
    await expect(
      discoverAccountCells(clientFor([changedState, asset], changedState), verified),
    ).rejects.toThrow(/state data/i);
  });
});

describe("fixed AccountLock spend", () => {
  it("builds one input, two occupied outputs, and exactly three ordered code deps", async () => {
    const { verified, state, asset } = fixtures();
    const prepared = await prepareSpend({
      client: clientFor([state, asset], state),
      account: verified,
      funderAddress: FUNDER_ADDRESS,
      passkey,
    });
    const tx = prepared.transaction;

    expect(tx.inputs).toHaveLength(1);
    expect(tx.inputs[0]!.previousOutput.eq(asset.outPoint)).toBe(true);
    expect(tx.outputs).toHaveLength(2);
    expect(tx.outputs[0]!.capacity).toBe(TRANSFER_CAPACITY);
    expect(tx.outputs[1]!.lock.eq(verified.accountLock)).toBe(true);
    expect(tx.outputsData).toEqual(["0x", "0x"]);
    expect(tx.cellDeps.map((dep) => [dep.outPoint.txHash, dep.depType])).toEqual([
      [deployment.artifacts.account_lock.txHash, "code"],
      [deployment.artifacts.verifier_p256.txHash, "code"],
      [verified.manifest.state_out_point.tx_hash, "code"],
    ]);
    for (const output of tx.outputs) {
      expect(output.capacity).toBeGreaterThanOrEqual(BigInt(output.occupiedSize) * SHANNONS_PER_CKB);
    }
    expect(prepared.review.feeShannons).toBe(tx.estimateFee(FEE_RATE).toString());
    expect(
      tx.outputs[0]!.capacity + tx.outputs[1]!.capacity + BigInt(prepared.review.feeShannons),
    ).toBe(asset.cellOutput.capacity);
  });

  it("keeps raw fields and the authorization digest fixed when inserting the real assertion", async () => {
    const { verified, state, asset } = fixtures();
    const prepared = await prepareSpend({
      client: clientFor([state, asset], state),
      account: verified,
      funderAddress: FUNDER_ADDRESS,
      passkey,
    });
    const rawHash = prepared.transaction.hash();
    const assertion: AssertionMaterial = {
      credentialId: passkey.credentialId,
      authenticatorData: ccc.bytesFrom(vector.inputs.authenticator_data),
      clientDataJson: new TextEncoder().encode(JSON.stringify({
        type: "webauthn.get",
        challenge: Buffer.from(prepared.authorizationDigest).toString("base64url"),
        origin: passkey.origin,
        crossOrigin: false,
      })),
      signature: Uint8Array.of(0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1),
    };

    const finalized = finalizeSpend(prepared, passkey, assertion);
    const finalizedGroupSighash = groupSighash(
      ccc.bytesFrom(finalized.hash()),
      [ccc.bytesFrom(finalized.witnesses[0]!)],
      [],
    );
    const finalizedDigest = authorizationDigest({
      operation: OP_SPEND,
      accountId: ccc.bytesFrom(prepared.accountId),
      sequence: prepared.sequence,
      state: ccc.bytesFrom(prepared.stateData),
      groupSighash: finalizedGroupSighash,
    });

    expect(finalized.hash()).toBe(rawHash);
    expect(ccc.hexFrom(finalizedDigest)).toBe(ccc.hexFrom(prepared.authorizationDigest));
    expect(ccc.bytesFrom(finalized.witnesses[0]!)).toHaveLength(
      finalized.witnesses[0]!.length / 2 - 1,
    );
    expect(ccc.bytesFrom(finalized.witnesses[0]!).length).toBeLessThanOrEqual(
      prepared.maxWitnessBytes,
    );
  });

  it("rejects an oversized assertion and credential substitution", async () => {
    const { verified, state, asset } = fixtures();
    const prepared = await prepareSpend({
      client: clientFor([state, asset], state),
      account: verified,
      funderAddress: FUNDER_ADDRESS,
      passkey,
    });
    const base: AssertionMaterial = {
      credentialId: "different",
      authenticatorData: new Uint8Array(37),
      clientDataJson: Uint8Array.of(1),
      signature: Uint8Array.of(1),
    };
    expect(() => finalizeSpend(prepared, passkey, base)).toThrow(/credential/i);
    expect(() => finalizeSpend(prepared, passkey, {
      ...base,
      credentialId: passkey.credentialId,
      authenticatorData: new Uint8Array(1025),
    })).toThrow(/authenticator/i);
  });
});

describe("submission and confirmation receipts", () => {
  it("submits exactly once and rescans the committed change", async () => {
    const txHash = `0x${"aa".repeat(32)}`;
    const asset = fixtures().asset;
    const change = ccc.Cell.from({
      outPoint: { txHash, index: 1 },
      cellOutput: {
        capacity: 99n * SHANNONS_PER_CKB,
        lock: asset.cellOutput.lock,
      },
      outputData: "0x",
    });
    const client = {
      sendTransaction: vi.fn(async () => txHash),
      waitTransaction: vi.fn(async () => ({ status: "committed" })),
      getCellLive: vi.fn(async () => change),
    } as unknown as SpendClient;
    const tx = ccc.Transaction.from({ outputs: [
      { capacity: TRANSFER_CAPACITY, lock: change.cellOutput.lock },
      { capacity: 99n * SHANNONS_PER_CKB, lock: change.cellOutput.lock },
    ], outputsData: ["0x", "0x"] });

    const submitted = await submitSpend(client, tx);
    const committed = await confirmSpend(client, submitted);

    expect(client.sendTransaction).toHaveBeenCalledTimes(1);
    expect(client.waitTransaction).toHaveBeenCalledWith(txHash, 0, 300_000);
    expect(client.getCellLive).toHaveBeenCalledWith({ txHash, index: 1 }, true, true);
    expect(committed).toMatchObject({ status: "committed", txHash });
  });

  it("preserves the submitted hash on confirmation timeout without resubmitting", async () => {
    const txHash = `0x${"bb".repeat(32)}`;
    const timeout = new ccc.ErrorClientWaitTransactionTimeout(300_000);
    const client = {
      sendTransaction: vi.fn(),
      waitTransaction: vi.fn(async () => { throw timeout; }),
      getCellLive: vi.fn(),
    } as unknown as SpendClient;
    const submitted = {
      status: "submitted" as const,
      txHash,
      explorerUrl: `https://pudge.explorer.nervos.org/transaction/${txHash}`,
      remainingCapacityShannons: "9900000000",
    };

    await expect(confirmSpend(client, submitted)).resolves.toMatchObject({
      status: "confirmation_timeout",
      txHash,
    });
    expect(client.sendTransaction).not.toHaveBeenCalled();
    expect(client.getCellLive).not.toHaveBeenCalled();
  });
});
