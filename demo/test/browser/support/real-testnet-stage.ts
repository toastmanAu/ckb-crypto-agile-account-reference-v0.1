import { expect, type Page } from "@playwright/test";

import type { VisibleStage } from "../../support/real-testnet-state.js";

const SETTLED_STAGE_TIMEOUT_MS = 30_000;

async function detectedStage(page: Page): Promise<VisibleStage | undefined> {
  if (
    await page.getByRole("heading", { name: "Local setup is blocked" }).isVisible()
    || await page.getByRole("alert").first().isVisible()
  ) {
    return "blocked";
  }
  const candidates: [VisibleStage, string][] = [
    ["create_passkey", "Create your passkey"],
    ["create_account", "Create your testnet account"],
    ["authorize_spend", "Authorize your first spend"],
    ["submitted", "Transaction submitted"],
    ["committed", "Spend committed"],
  ];
  for (const [stage, heading] of candidates) {
    if (await page.getByRole("heading", { name: heading }).isVisible()) return stage;
  }
  return undefined;
}

export async function visibleStage(page: Page): Promise<VisibleStage> {
  let stage: VisibleStage | undefined;
  await expect.poll(async () => {
    stage = await detectedStage(page);
    return stage;
  }, {
    message: "waiting for a settled real-testnet stage",
    timeout: SETTLED_STAGE_TIMEOUT_MS,
    intervals: [50, 100, 250, 500],
  }).not.toBeUndefined();
  if (stage === undefined) throw new Error("No recognized real-testnet stage became visible");
  return stage;
}
