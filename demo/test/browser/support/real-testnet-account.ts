import type { Page } from "@playwright/test";

import {
  AccountManifestSchema,
  type AccountManifest,
} from "../../../src/shared/schemas.js";

export async function readAccountManifest(
  page: Page,
  timeoutMs: number,
): Promise<AccountManifest> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("Account manifest timeout must be a positive integer");
  }
  const value: unknown = await page.evaluate(async (localTimeoutMs) => {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), localTimeoutMs);
    try {
      const response = await fetch("/api/account", {
        headers: { accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`account manifest request failed with ${response.status}`);
      return response.json();
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }, timeoutMs);
  return AccountManifestSchema.parse(value);
}
