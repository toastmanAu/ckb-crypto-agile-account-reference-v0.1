import {
  ArtifactIdentity,
  VerifiedArtifact,
  codeCellCapacityShannons,
  loadVerifiedArtifact,
  readLocalArtifactIdentities,
} from "./artifacts.js";

/**
 * The phased first deployment: AccountLock plus the WebAuthn ES256/P-256
 * verifier. This proves Type ID state creation, the CKB2023 spawn/pipe ABI, and
 * the passkey spend path on a real chain before any post-quantum verifier is
 * published.
 */
export const PHASED_P256_ARTIFACTS = ["account_lock", "verifier_p256"];

/** Every artifact this repository can publish as a code cell. */
export const ALL_ARTIFACTS = [
  "account_lock",
  "verifier_p256",
  "verifier_mldsa65",
  "verifier_slhdsa_sha2_128s",
];

export interface PlannedCell extends ArtifactIdentity {
  data: Uint8Array;
  capacityShannons: bigint;
}

export interface DeploymentPlan {
  cells: PlannedCell[];
  totalCapacityShannons: bigint;
}

/**
 * Builds an immutable-code-cell deployment plan.
 *
 * Every selected artifact is hash-verified against the recorded local identity
 * before it enters the plan, so a stale or debug binary cannot reach a
 * transaction builder.
 */
export function buildDeploymentPlan(
  repoRoot: string,
  selection: string[],
  lockArgsLength: number,
): DeploymentPlan {
  if (selection.length === 0) {
    throw new Error("no artifacts selected for deployment");
  }

  const duplicates = selection.filter(
    (name, index) => selection.indexOf(name) !== index,
  );
  if (duplicates.length > 0) {
    throw new Error(
      `duplicate artifact in selection: ${[...new Set(duplicates)].join(", ")}`,
    );
  }

  const identities = readLocalArtifactIdentities(repoRoot);
  const cells = selection.map((name) => {
    const identity = identities[name];
    if (!identity) {
      throw new Error(
        `unknown artifact '${name}'; known artifacts: ${Object.keys(identities).join(", ")}`,
      );
    }
    const verified: VerifiedArtifact = loadVerifiedArtifact(repoRoot, identity);
    return {
      ...verified,
      capacityShannons: codeCellCapacityShannons(verified.data.length, lockArgsLength),
    };
  });

  return {
    cells,
    totalCapacityShannons: cells.reduce(
      (total, cell) => total + cell.capacityShannons,
      0n,
    ),
  };
}

/** Formats shannons as a human-readable CKB amount. */
export function formatCkb(shannons: bigint): string {
  const whole = shannons / 100_000_000n;
  const fraction = shannons % 100_000_000n;
  return fraction === 0n
    ? `${whole.toLocaleString("en-US")} CKB`
    : `${whole.toLocaleString("en-US")}.${fraction.toString().padStart(8, "0").replace(/0+$/, "")} CKB`;
}
