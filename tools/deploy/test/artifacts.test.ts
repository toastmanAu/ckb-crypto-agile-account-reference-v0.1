import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  cellCapacityShannons,
  ckbDataHash,
  codeCellCapacityShannons,
  loadVerifiedArtifact,
  readLocalArtifactIdentities,
  SECP256K1_LOCK_ARGS_LENGTH,
} from "../src/artifacts.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("ckbDataHash", () => {
  // The Rust `export_artifact_manifest` example is the oracle here: these
  // hashes are what the reference implementation itself recorded in
  // deploy/reference-deployments.json. A TypeScript deployer that computes a
  // different data hash would publish a cell the AccountState can never
  // reference.
  it("reproduces every data hash the Rust exporter recorded", () => {
    const identities = readLocalArtifactIdentities(repoRoot);
    expect(Object.keys(identities).length).toBeGreaterThan(0);

    for (const [name, identity] of Object.entries(identities)) {
      const data = readFileSync(resolve(repoRoot, identity.path));
      expect(ckbDataHash(data), `data hash for ${name}`).toBe(identity.dataHash);
    }
  });

  it("is not a plain blake2b digest without the CKB personalization", () => {
    // Guards against reaching for an unpersonalized hash: the CKB default hash
    // uses the "ckb-default-hash" personalization, so an empty input has a
    // known, distinctive digest. Independently reproduced with
    // `hashlib.blake2b(b"", digest_size=32, person=b"ckb-default-hash")`.
    expect(ckbDataHash(new Uint8Array())).toBe(
      "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e",
    );
  });
});

describe("codeCellCapacityShannons", () => {
  it("charges for the capacity field, lock script, and data", () => {
    // 8 (capacity) + 32 (code_hash) + 1 (hash_type) + 20 (args) + data
    const capacity = codeCellCapacityShannons(0, SECP256K1_LOCK_ARGS_LENGTH);
    expect(capacity).toBe(61n * 100_000_000n);
  });

  it("scales one shannon-per-byte-of-CKB with the payload", () => {
    const capacity = codeCellCapacityShannons(33_448, SECP256K1_LOCK_ARGS_LENGTH);
    expect(capacity).toBe(33_509n * 100_000_000n);
  });
});

describe("loadVerifiedArtifact", () => {
  it("returns the bytes when the data hash matches the recorded identity", () => {
    const identities = readLocalArtifactIdentities(repoRoot);
    const identity = identities.account_lock;

    const artifact = loadVerifiedArtifact(repoRoot, identity);

    expect(artifact.dataHash).toBe(identity.dataHash);
    expect(artifact.data.length).toBeGreaterThan(0);
  });

  it("refuses an artifact whose data hash does not match", () => {
    const identities = readLocalArtifactIdentities(repoRoot);
    const tampered = {
      ...identities.account_lock,
      dataHash: `0x${"00".repeat(32)}`,
    };

    expect(() => loadVerifiedArtifact(repoRoot, tampered)).toThrow(
      /data hash mismatch/i,
    );
  });

  it("refuses a debug build standing in for a release artifact", () => {
    const identities = readLocalArtifactIdentities(repoRoot);
    const wrongPath = {
      ...identities.account_lock,
      path: identities.account_lock.path.replace("/release/", "/debug/"),
    };

    // Either the debug ELF is absent or it hashes differently; both must fail
    // closed rather than deploy an unreproducible binary.
    expect(() => loadVerifiedArtifact(repoRoot, wrongPath)).toThrow();
  });
});

describe("cellCapacityShannons", () => {
  it("charges for a type script when the cell has one", () => {
    // 8 capacity + lock(32+1+33) + type(32+1+32) + 177 data = 316 bytes
    const capacity = cellCapacityShannons({
      lockArgsLength: 33,
      typeArgsLength: 32,
      dataLength: 177,
    });
    expect(capacity).toBe(316n * 100_000_000n);
  });

  it("omits the type script cost when there is none", () => {
    const capacity = cellCapacityShannons({
      lockArgsLength: 33,
      typeArgsLength: null,
      dataLength: 0,
    });
    // 8 + (32+1+33) = 74 bytes
    expect(capacity).toBe(74n * 100_000_000n);
  });

  it("agrees with codeCellCapacityShannons for a type-less cell", () => {
    expect(
      cellCapacityShannons({ lockArgsLength: 20, typeArgsLength: null, dataLength: 33_448 }),
    ).toBe(codeCellCapacityShannons(33_448, SECP256K1_LOCK_ARGS_LENGTH));
  });
});
