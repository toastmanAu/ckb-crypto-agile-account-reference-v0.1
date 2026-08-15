import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { ccc } from "@ckb-ccc/core";

/** Byte length of a secp256k1_blake160_sighash_all lock's args. */
export const SECP256K1_LOCK_ARGS_LENGTH = 20;

/** Occupied bytes of a cell's own capacity field. */
const CAPACITY_FIELD_BYTES = 8;

/** Occupied bytes of a script, excluding its args. */
const SCRIPT_FIXED_BYTES = 32 /* code_hash */ + 1; /* hash_type */

/** Shannons per CKB. */
const SHANNONS_PER_CKB = 100_000_000n;

export interface ArtifactIdentity {
  /** Manifest key, e.g. `account_lock`. */
  name: string;
  /** Repository-relative path to the release ELF. */
  path: string;
  /** CKB data hash recorded by the Rust `export_artifact_manifest` example. */
  dataHash: string;
}

export interface VerifiedArtifact extends ArtifactIdentity {
  data: Uint8Array;
}

/**
 * CKB's default hash: blake2b-256 personalized with `ckb-default-hash`.
 *
 * This must agree byte-for-byte with the Rust implementation's `ckb_hash`,
 * because a code cell is referenced by this value. Deploying under a different
 * hash publishes a cell that no AccountState VerifierRef can resolve.
 */
export function ckbDataHash(data: Uint8Array): string {
  return ccc.hashCkb(data);
}

/**
 * Minimum capacity, in shannons, for a code cell holding `dataLength` bytes
 * under a lock with `lockArgsLength` bytes of args and no type script.
 */
export function codeCellCapacityShannons(
  dataLength: number,
  lockArgsLength: number,
): bigint {
  if (!Number.isInteger(dataLength) || dataLength < 0) {
    throw new Error(`invalid data length: ${dataLength}`);
  }
  if (!Number.isInteger(lockArgsLength) || lockArgsLength < 0) {
    throw new Error(`invalid lock args length: ${lockArgsLength}`);
  }
  const occupiedBytes =
    CAPACITY_FIELD_BYTES + SCRIPT_FIXED_BYTES + lockArgsLength + dataLength;
  return BigInt(occupiedBytes) * SHANNONS_PER_CKB;
}

interface DeploymentManifest {
  local?: {
    artifacts?: Record<string, { path?: string; data_hash?: string }>;
  };
}

/**
 * Reads the local artifact identities the Rust exporter recorded in
 * `deploy/reference-deployments.json`.
 */
export function readLocalArtifactIdentities(
  repoRoot: string,
): Record<string, ArtifactIdentity> {
  const manifestPath = resolve(repoRoot, "deploy/reference-deployments.json");
  const manifest = JSON.parse(
    readFileSync(manifestPath, "utf8"),
  ) as DeploymentManifest;

  const artifacts = manifest.local?.artifacts;
  if (!artifacts) {
    throw new Error(`${manifestPath} has no local.artifacts section`);
  }

  const identities: Record<string, ArtifactIdentity> = {};
  for (const [name, entry] of Object.entries(artifacts)) {
    if (!entry?.path || !entry?.data_hash) {
      throw new Error(`${manifestPath}: artifact ${name} is missing path or data_hash`);
    }
    identities[name] = { name, path: entry.path, dataHash: entry.data_hash };
  }
  return identities;
}

/**
 * Loads an artifact and refuses to return it unless its data hash matches the
 * recorded identity.
 *
 * This is the guard against publishing a debug build, a stale ELF, or a binary
 * from a dirty checkout. A code cell is immutable once published, so this check
 * has no second chance.
 */
export function loadVerifiedArtifact(
  repoRoot: string,
  identity: ArtifactIdentity,
): VerifiedArtifact {
  const absolute = resolve(repoRoot, identity.path);
  let data: Uint8Array;
  try {
    data = readFileSync(absolute);
  } catch (error) {
    throw new Error(
      `cannot read artifact ${identity.name} at ${absolute}: ${String(error)}`,
    );
  }

  const actual = ckbDataHash(data);
  if (actual !== identity.dataHash) {
    throw new Error(
      `data hash mismatch for ${identity.name} at ${absolute}: ` +
        `expected ${identity.dataHash}, computed ${actual}. ` +
        `Rebuild with the pinned toolchain from a clean checkout before deploying.`,
    );
  }

  return { ...identity, data };
}
