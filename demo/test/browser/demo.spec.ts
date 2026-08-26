import {
  expect,
  test,
  type APIRequestContext,
} from "@playwright/test";

import {
  captureAndPersistRecovery,
  installVirtualAuthenticator,
} from "./support/virtual-authenticator.js";
import { createRealTestnetPaths } from "../support/real-testnet-state.js";

const CONTROL_HEADERS = { "x-test-control": "ckb-passkey-demo" };

async function setFixtureControl(
  request: APIRequestContext,
  control: { confirmation?: "committed" | "timeout"; change?: "live" | "missing" },
): Promise<void> {
  const response = await request.post("http://127.0.0.1:8790/__test__/control", {
    headers: CONTROL_HEADERS,
    data: control,
  });
  expect(response.ok()).toBe(true);
}

async function fixtureEvents(request: APIRequestContext): Promise<{
  sendTransactions: number;
  confirmationChecks: number;
  confirmationResponses: number;
  changeScans: number;
}> {
  const response = await request.get("http://127.0.0.1:8790/__test__/control/events", {
    headers: CONTROL_HEADERS,
  });
  expect(response.ok()).toBe(true);
  return response.json();
}

test.beforeEach(async ({ request }) => {
  const response = await request.post("http://127.0.0.1:8790/__test__/control/reset", {
    headers: CONTROL_HEADERS,
  });
  expect(response.ok()).toBe(true);
});

test("registers a real virtual passkey before offering account bootstrap", async ({ page }) => {
  await installVirtualAuthenticator(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
  await page.getByRole("button", { name: "Create passkey" }).click();

  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
  await expect(page.getByText(/passkey key ID/i)).toBeVisible();
});

test("backs up and restores the virtual passkey before a spend", async ({ page }, testInfo) => {
  const paths = createRealTestnetPaths(testInfo.outputPath("repo-root"));
  const first = await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();

  const recovery = await captureAndPersistRecovery(
    page,
    first,
    paths,
    new Date("2026-08-26T00:00:00.000Z"),
  );
  await first.session.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: first.authenticatorId,
  });
  await installVirtualAuthenticator(page, { recovery });

  await page.getByRole("button", { name: "Create testnet account" }).click();
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
});

test("authorizes the fixed spend and preserves its submitted and committed receipt", async ({ page }) => {
  await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("button", { name: "Create testnet account" }).click();

  await expect(page.getByRole("heading", { name: "Authorize your first spend" })).toBeVisible();
  const review = page.getByRole("region", { name: "Authorize your first spend" });
  await expect(review.getByText("200 CKB", { exact: true })).toBeVisible();
  await expect(review.getByText("100 CKB", { exact: true })).toBeVisible();
  await expect(review.getByText("99.99996253 CKB", { exact: true })).toBeVisible();
  await expect(review.getByText("0.00003747 CKB", { exact: true })).toBeVisible();
  await expect(review.getByText("AccountLock code", { exact: true })).toBeVisible();
  await expect(review.getByText("P-256 verifier code", { exact: true })).toBeVisible();
  await expect(review.getByText("AccountState cell", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();

  await expect(page.getByRole("heading", { name: "Transaction submitted" })).toBeVisible();
  const submittedHash = page.getByLabel(/Transaction hash 0x/);
  await expect(submittedHash).toBeVisible();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
  await expect(page.getByText(/verified AccountLock change/i)).toBeVisible();
  await expect(submittedHash).toBeVisible();
});

test("returns a cancelled passkey ceremony to a retryable action", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page, { userVerified: false });
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();

  await expect(page.getByRole("status")).toContainText("cancelled");
  await authenticator.session.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.authenticatorId,
    isUserVerified: true,
  });
  await page.getByRole("button", { name: "Create passkey" }).click();

  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
});

test("retries a cancelled spend assertion without submitting the frozen review", async ({ page, request }) => {
  const authenticator = await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await expect(page.getByRole("heading", { name: "Authorize your first spend" })).toBeVisible();

  await authenticator.session.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.authenticatorId,
    isUserVerified: false,
  });
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();
  await expect(page.getByRole("status")).toContainText("Passkey authorization was cancelled");
  await expect.poll(async () => (await fixtureEvents(request)).sendTransactions).toBe(0);

  await authenticator.session.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.authenticatorId,
    isUserVerified: true,
  });
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
  await expect.poll(async () => (await fixtureEvents(request)).sendTransactions).toBe(1);
});

test("resumes from browser and authoritative server state after refresh", async ({ page }) => {
  await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await expect(page.getByRole("heading", { name: "Authorize your first spend" })).toBeVisible();

  await page.reload();
  const resumed = page.getByRole("region", { name: "Authorize your first spend" });
  await expect(resumed.getByText("200 CKB", { exact: true })).toBeVisible();
  await expect(resumed.getByRole("button", { name: "Authorize 100 CKB spend" })).toBeEnabled();
});

test("moves focus from each stage heading to its one primary action", async ({ page }) => {
  await installVirtualAuthenticator(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Create passkey" })).toBeFocused();
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Create testnet account" })).toBeFocused();
});

test("reduces spinner motion when the browser requests reduced motion", async ({ browser }) => {
  const context = await browser.newContext({
    baseURL: "http://localhost:5173",
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page, { automaticPresence: false });
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();

  const spinner = page.locator(".spinner");
  await expect(spinner).toBeVisible();
  await expect(spinner).toHaveCSS("animation-duration", "0.001s");
  await expect(spinner).toHaveCSS("animation-iteration-count", "1");

  await authenticator.session.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: authenticator.authenticatorId,
  });
  await context.close();
});

test("preserves a timed-out hash and checks it again without resubmitting", async ({ page, request }) => {
  await setFixtureControl(request, { confirmation: "timeout" });
  await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await page.clock.install();
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();

  await expect(page.getByRole("heading", { name: "Transaction submitted" })).toBeVisible();
  const receiptHash = page.getByLabel(/Transaction hash 0x/);
  await expect(receiptHash).toBeVisible();
  await expect.poll(async () => (await fixtureEvents(request)).confirmationResponses).toBe(1);
  await new Promise((resolve) => setTimeout(resolve, 100));
  await page.clock.fastForward(301_000);
  await expect(page.getByRole("status")).toContainText("taking longer than expected");

  await setFixtureControl(request, { confirmation: "committed" });
  await page.getByRole("button", { name: "Check again" }).click();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
  await expect(receiptHash).toBeVisible();
  await expect.poll(async () => (await fixtureEvents(request)).sendTransactions).toBe(1);
});

test("keeps the receipt submitted until the committed change rescans live", async ({ page, request }) => {
  await setFixtureControl(request, { change: "missing" });
  await installVirtualAuthenticator(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();

  await expect(page.getByRole("heading", { name: "Transaction submitted" })).toBeVisible();
  await expect.poll(async () => (await fixtureEvents(request)).changeScans).toBe(1);
  await expect(page.getByRole("heading", { name: "Spend committed" })).not.toBeVisible();

  await setFixtureControl(request, { change: "live" });
  await page.getByRole("button", { name: "Check again" }).click();
  await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible();
  await expect.poll(async () => (await fixtureEvents(request)).sendTransactions).toBe(1);
});
