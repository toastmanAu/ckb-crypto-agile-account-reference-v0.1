import { describe, expect, it } from "vitest";

import { ApiError } from "../../src/server/errors.js";
import {
  createDemoService,
  type DemoServiceDeps,
  type LiveStateCell,
} from "../../src/server/service.js";
import type {
  AccountManifest,
  BootstrapRequest,
  DeploymentManifest,
} from "../../src/shared/schemas.js";

const HASH = (byte: string) => `0x${byte.repeat(64)}`;
const ACCOUNT_ID = HASH("1");
const ACCOUNT_LOCK_HASH =
  "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e";
const STATE_TX_HASH = HASH("3");
const PUBLIC_KEY = `0x04${"11".repeat(64)}`;
const request: BootstrapRequest = { publicKey: PUBLIC_KEY, credentialId: "AQIDBA" };

const deployment = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: ACCOUNT_LOCK_HASH,
      hashType: "data2",
      txHash: HASH("b"),
      index: 0,
      capacityShannons: "3350900000000",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: ACCOUNT_LOCK_HASH,
      hashType: "data2",
      txHash: HASH("d"),
      index: 0,
      capacityShannons: "6218100000000",
    },
  },
} satisfies DeploymentManifest;

const account = {
  schema_version: 1,
  network: "testnet",
  account_id: ACCOUNT_ID,
  account_lock: {
    code_hash: ACCOUNT_LOCK_HASH,
    hash_type: "data2",
    args: `0x01${"1".repeat(64)}`,
  },
  type_id_args: HASH("2"),
  state_out_point: { tx_hash: STATE_TX_HASH, index: 0 },
  asset_out_point: { tx_hash: STATE_TX_HASH, index: 1 },
  state_bytes: 3,
} satisfies AccountManifest;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function harness(options: {
  manifest?: unknown;
  stateCell?: LiveStateCell | null;
  exportedState?: Uint8Array;
  balance?: bigint;
  bootstrap?: Promise<AccountManifest>;
  deploymentCell?: LiveStateCell | null;
  deploymentError?: Error;
} = {}) {
  let manifest = options.manifest === undefined ? null : options.manifest;
  let exports = 0;
  let broadcasts = 0;
  const deps: DemoServiceDeps = {
    deployment,
    async funderAddress() {
      return "ckt1-funder";
    },
    async funderBalanceShannons() {
      return options.balance ?? 1_000_000_000_000n;
    },
    readAccountManifest() {
      return manifest;
    },
    async getDeploymentCell() {
      if (options.deploymentError) throw options.deploymentError;
      return options.deploymentCell === undefined
        ? { outputData: "0x" }
        : options.deploymentCell;
    },
    async getStateCell() {
      return options.stateCell ?? null;
    },
    async exportState() {
      exports += 1;
      return options.exportedState ?? Uint8Array.of(1, 2, 3);
    },
    async bootstrap() {
      broadcasts += 1;
      const created = options.bootstrap ? await options.bootstrap : account;
      manifest = created;
      return created;
    },
  };
  return {
    deps,
    service: createDemoService(deps),
    exports: () => exports,
    broadcasts: () => broadcasts,
  };
}

describe("DemoService status and account", () => {
  it("reports only public testnet deployment and funder status", async () => {
    const run = harness({ manifest: account });
    await expect(run.service.status()).resolves.toEqual({
      schemaVersion: 1,
      network: "testnet",
      origin: "http://localhost:5173",
      rpId: "localhost",
      deploymentVerified: true,
      deployment,
      funderAddress: "ckt1-funder",
      funderBalanceShannons: "1000000000000",
      account,
    });
  });

  it("returns null when no account exists and rejects malformed metadata", async () => {
    await expect(harness().service.account()).resolves.toBeNull();
    await expect(harness({ manifest: { schema_version: 9 } }).service.account()).rejects.toMatchObject({
      code: "ACCOUNT_MISMATCH",
    });
  });

  it("fails construction when the code-cell deployment is not verified", () => {
    expect(() =>
      createDemoService({
        ...harness().deps,
        deployment: { ...deployment, network: "mainnet" },
      } as DemoServiceDeps),
    ).toThrowError(ApiError);
  });

  it("re-reads both deployment outpoints and rejects missing or mismatched code data", async () => {
    await expect(harness({ deploymentCell: null }).service.status()).rejects.toMatchObject({
      code: "DEPLOYMENT_INVALID",
    });
    await expect(
      harness({ deploymentCell: { outputData: "0x01" } }).service.status(),
    ).rejects.toMatchObject({ code: "DEPLOYMENT_INVALID" });
    await expect(
      harness({ deploymentError: new Error("private RPC detail") }).service.status(),
    ).rejects.toMatchObject({ code: "DEPLOYMENT_INVALID" });
  });
});

describe("DemoService bootstrap", () => {
  it("returns an existing account only after exact on-chain state comparison", async () => {
    const matching = harness({
      manifest: account,
      stateCell: { outputData: "0x010203" },
    });
    await expect(matching.service.bootstrap(request)).resolves.toEqual(account);
    expect(matching.exports()).toBe(1);
    expect(matching.broadcasts()).toBe(0);

    const mismatch = harness({
      manifest: account,
      stateCell: { outputData: "0x010204" },
    });
    await expect(mismatch.service.bootstrap(request)).rejects.toMatchObject({
      code: "ACCOUNT_MISMATCH",
    });
    expect(mismatch.broadcasts()).toBe(0);
  });

  it("rejects missing live state and insufficient bootstrap capacity", async () => {
    await expect(
      harness({ manifest: account, stateCell: null }).service.bootstrap(request),
    ).rejects.toMatchObject({ code: "ACCOUNT_MISMATCH" });
    await expect(harness({ balance: 1n }).service.bootstrap(request)).rejects.toMatchObject({
      code: "INSUFFICIENT_BALANCE",
    });
  });

  it("maps exporter and confirmation failures to stable errors", async () => {
    const exporter = harness();
    exporter.deps.exportState = async () => {
      throw new Error("private exporter detail");
    };
    await expect(exporter.service.bootstrap(request)).rejects.toMatchObject({
      code: "BOOTSTRAP_FAILED",
    });

    const timedOut = new Error("RPC included private detail");
    timedOut.name = "ErrorClientWaitTransactionTimeout";
    const timeout = harness({ bootstrap: Promise.reject(timedOut) });
    await expect(timeout.service.bootstrap(request)).rejects.toMatchObject({
      code: "CONFIRMATION_TIMEOUT",
    });
  });

  it("serializes matching concurrent creation and exposes metadata only after completion", async () => {
    const creation = deferred<AccountManifest>();
    const run = harness({ bootstrap: creation.promise });

    const first = run.service.bootstrap(request);
    const second = run.service.bootstrap(request);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(run.broadcasts()).toBe(1);
    await expect(run.service.account()).resolves.toBeNull();

    creation.resolve(account);
    await expect(Promise.all([first, second])).resolves.toEqual([account, account]);
    expect(run.broadcasts()).toBe(1);
    await expect(run.service.account()).resolves.toEqual(account);
  });

  it("rejects a different request while account creation is in flight", async () => {
    const creation = deferred<AccountManifest>();
    const run = harness({ bootstrap: creation.promise });
    const first = run.service.bootstrap(request);
    const different = { ...request, publicKey: `0x04${"22".repeat(64)}` };

    await expect(run.service.bootstrap(different)).rejects.toMatchObject({
      code: "ACCOUNT_MISMATCH",
    });
    creation.resolve(account);
    await first;
    expect(run.broadcasts()).toBe(1);
  });
});
