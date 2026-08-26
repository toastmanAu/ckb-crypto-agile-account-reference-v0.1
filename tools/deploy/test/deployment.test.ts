import { describe, expect, it } from "vitest";

import {
  buildDeploymentManifest,
  parseDeploymentArgs,
  type DeployedRecord,
} from "../src/deployment.js";

const accountLock: DeployedRecord = {
  name: "account_lock",
  dataHash: `0x${"11".repeat(32)}`,
  hashType: "data2",
  txHash: `0x${"22".repeat(32)}`,
  index: 0,
  capacityShannons: "3350900000000",
};

const oldVerifier: DeployedRecord = {
  name: "verifier_p256",
  dataHash: `0x${"33".repeat(32)}`,
  hashType: "data2",
  txHash: `0x${"44".repeat(32)}`,
  index: 0,
  capacityShannons: "6218100000000",
};

const correctedVerifier: DeployedRecord = {
  ...oldVerifier,
  dataHash: `0x${"55".repeat(32)}`,
  txHash: `0x${"66".repeat(32)}`,
};

describe("parseDeploymentArgs", () => {
  it("selects only the named verifier for a selective broadcast", () => {
    expect(parseDeploymentArgs(["--broadcast", "--only", "verifier_p256"])).toEqual({
      broadcast: true,
      selection: ["verifier_p256"],
    });
  });

  it.each([
    [["--only"], /requires an artifact/i],
    [["--all", "--only", "verifier_p256"], /cannot combine/i],
    [["--only", "unknown_verifier"], /unknown artifact/i],
  ] as const)("rejects unsafe selection arguments %j", (argv, expected) => {
    expect(() => parseDeploymentArgs([...argv])).toThrow(expected);
  });
});

describe("buildDeploymentManifest", () => {
  it("retains the published AccountLock while replacing only the corrected verifier", () => {
    const existing = {
      schema_version: 1,
      network: "testnet",
      published: true,
      hash_type: "data2",
      note: "previous deployment",
      artifacts: {
        account_lock: accountLock,
        verifier_p256: oldVerifier,
      },
    };

    expect(buildDeploymentManifest(existing, [correctedVerifier]).artifacts).toEqual({
      account_lock: accountLock,
      verifier_p256: correctedVerifier,
    });
  });

  it("rejects malformed existing manifests instead of silently dropping deployment records", () => {
    expect(() => buildDeploymentManifest({ artifacts: { account_lock: accountLock } }, [
      correctedVerifier,
    ])).toThrow(/existing deployment manifest/i);
  });
});
