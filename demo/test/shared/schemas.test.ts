import { describe, expect, it } from "vitest";

import {
  AccountManifestSchema,
  BootstrapRequestSchema,
  DeploymentManifestSchema,
} from "../../src/shared/schemas.js";

const hash = `0x${"11".repeat(32)}`;
const accountArgs = `0x01${"11".repeat(32)}`;
const publicKey = `0x04${"33".repeat(64)}`;
const credentialId = "AQIDBA";

const deployment = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  note: "verified",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: hash,
      hashType: "data2",
      txHash: hash,
      index: 0,
      capacityShannons: "3350900000000",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: hash,
      hashType: "data2",
      txHash: hash,
      index: 0,
      capacityShannons: "6218100000000",
    },
  },
} as const;

const account = {
  schema_version: 1,
  network: "testnet",
  account_id: hash,
  account_lock: {
    code_hash: hash,
    hash_type: "data2",
    args: accountArgs,
  },
  type_id_args: hash,
  state_out_point: { tx_hash: hash, index: 0 },
  asset_out_point: { tx_hash: hash, index: 1 },
  state_bytes: 145,
} as const;

describe("public manifest schemas", () => {
  it("accepts the two verified testnet deployment records", () => {
    expect(DeploymentManifestSchema.parse(deployment)).toEqual(deployment);
  });

  it.each([
    ["mainnet", { ...deployment, network: "mainnet" }],
    ["non-data2", { ...deployment, hash_type: "data" }],
    ["missing outpoint", {
      ...deployment,
      artifacts: {
        ...deployment.artifacts,
        account_lock: { ...deployment.artifacts.account_lock, txHash: undefined },
      },
    }],
    ["short hash", {
      ...deployment,
      artifacts: {
        ...deployment.artifacts,
        verifier_p256: { ...deployment.artifacts.verifier_p256, dataHash: "0x11" },
      },
    }],
  ])("rejects %s deployment data", (_label, value) => {
    expect(() => DeploymentManifestSchema.parse(value)).toThrow();
  });

  it("accepts the version-one account manifest", () => {
    expect(AccountManifestSchema.parse(account)).toEqual(account);
  });

  it("rejects AccountLock args that are not version plus account ID", () => {
    expect(() =>
      AccountManifestSchema.parse({
        ...account,
        account_lock: { ...account.account_lock, args: hash },
      }),
    ).toThrow();
  });
});

describe("bootstrap request boundary", () => {
  it("accepts only the public credential inputs", () => {
    expect(() => BootstrapRequestSchema.parse({ publicKey, credentialId })).not.toThrow();
  });

  it.each([
    ["network", "mainnet"],
    ["origin", "https://example.com"],
    ["rpId", "example.com"],
    ["amount", "1"],
    ["statePath", "/tmp/state.bin"],
  ])("rejects caller-supplied %s", (field, value) => {
    expect(() =>
      BootstrapRequestSchema.parse({ publicKey, credentialId, [field]: value }),
    ).toThrow();
  });
});
