import { describe, expect, it } from "vitest";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SECP256K1_LOCK_ARGS_LENGTH } from "../src/artifacts.js";
import { PHASED_P256_ARTIFACTS, buildDeploymentPlan } from "../src/plan.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("buildDeploymentPlan", () => {
  it("plans one code cell per artifact, sized from its verified bytes", () => {
    const plan = buildDeploymentPlan(repoRoot, ["account_lock"], SECP256K1_LOCK_ARGS_LENGTH);

    expect(plan.cells).toHaveLength(1);
    const [cell] = plan.cells;
    expect(cell.name).toBe("account_lock");
    expect(cell.dataHash).toBe(
      "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe",
    );
    // 33,448 bytes of ELF + 61 bytes of cell overhead
    expect(cell.capacityShannons).toBe(33_509n * 100_000_000n);
  });

  it("totals capacity across every planned cell", () => {
    const plan = buildDeploymentPlan(
      repoRoot,
      ["account_lock", "verifier_p256"],
      SECP256K1_LOCK_ARGS_LENGTH,
    );

    const sum = plan.cells.reduce((total, cell) => total + cell.capacityShannons, 0n);
    expect(plan.totalCapacityShannons).toBe(sum);
    // 33,509 + 62,181 CKB
    expect(plan.totalCapacityShannons).toBe(95_690n * 100_000_000n);
  });

  it("exposes the phased P-256 selection as AccountLock plus the P-256 verifier", () => {
    expect(PHASED_P256_ARTIFACTS).toEqual(["account_lock", "verifier_p256"]);
  });

  it("rejects an unknown artifact name instead of silently deploying nothing", () => {
    expect(() =>
      buildDeploymentPlan(repoRoot, ["verifier_falcon"], SECP256K1_LOCK_ARGS_LENGTH),
    ).toThrow(/unknown artifact/i);
  });

  it("rejects an empty selection", () => {
    expect(() => buildDeploymentPlan(repoRoot, [], SECP256K1_LOCK_ARGS_LENGTH)).toThrow(
      /no artifacts/i,
    );
  });

  it("refuses to plan a duplicate artifact", () => {
    expect(() =>
      buildDeploymentPlan(
        repoRoot,
        ["account_lock", "account_lock"],
        SECP256K1_LOCK_ARGS_LENGTH,
      ),
    ).toThrow(/duplicate/i);
  });
});
