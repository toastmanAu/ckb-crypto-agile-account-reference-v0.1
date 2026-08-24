import { expect, test, type CDPSession, type Page } from "@playwright/test";

const privateKeyIsValid = /^0x[0-9a-fA-F]{64}$/.test(process.env.CKB_PRIVKEY ?? "");
const realTestnetEnabled =
  process.env.CKB_PASSKEY_REAL_TESTNET_SPEC === "1" &&
  process.env.RUN_CKB_TESTNET === "1" &&
  privateKeyIsValid;

test.skip(
  !realTestnetEnabled,
  "real testnet browser coverage requires RUN_CKB_TESTNET=1 and a valid CKB_PRIVKEY",
);
test.describe.configure({ mode: "serial" });

const ACCOUNT_STATE_BYTES = 177;
const ACCOUNT_STATE_CAPACITY_CKB = 316;
const ACCOUNT_ASSET_CAPACITY_CKB = 200;
const BOOTSTRAP_FEE_RESERVE_CKB = 1;

interface PublicTransactionHashes {
  accountCreation?: string;
  spend?: string;
}

async function installVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return session;
}

function printCapacityPlan(): void {
  console.log(
    [
      "CKB testnet account capacity plan (before bootstrap):",
      `  AccountState cell (${ACCOUNT_STATE_BYTES} data bytes): ${ACCOUNT_STATE_CAPACITY_CKB} CKB`,
      `  AccountLock asset cell: ${ACCOUNT_ASSET_CAPACITY_CKB} CKB`,
      `  Fee reserve required by the local service: ${BOOTSTRAP_FEE_RESERVE_CKB} CKB`,
      `  Minimum funder balance: ${ACCOUNT_STATE_CAPACITY_CKB + ACCOUNT_ASSET_CAPACITY_CKB + BOOTSTRAP_FEE_RESERVE_CKB} CKB`,
    ].join("\n"),
  );
}

async function readAccountCreationHash(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const response = await fetch("/api/account", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`account manifest request failed with ${response.status}`);
    const value: unknown = await response.json();
    if (
      typeof value !== "object" ||
      value === null ||
      !("state_out_point" in value) ||
      typeof value.state_out_point !== "object" ||
      value.state_out_point === null ||
      !("tx_hash" in value.state_out_point) ||
      typeof value.state_out_point.tx_hash !== "string"
    ) {
      throw new Error("account manifest did not contain a state transaction hash");
    }
    return value.state_out_point.tx_hash;
  });
}

async function readDisplayedSpendHash(page: Page): Promise<string> {
  const label = await page.getByLabel(/Transaction hash 0x/).getAttribute("aria-label");
  const match = label?.match(/0x[0-9a-f]{64}/i);
  if (match === undefined || match === null) {
    throw new Error("submitted receipt did not expose a transaction hash");
  }
  return match[0];
}

test("completes the passkey account and fixed spend on CKB testnet", async ({ page }) => {
  test.setTimeout(20 * 60 * 1_000);
  const hashes: PublicTransactionHashes = {};
  await installVirtualAuthenticator(page);

  try {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();

    printCapacityPlan();
    await page.getByRole("button", { name: "Create testnet account" }).click();
    await expect(page.getByRole("heading", { name: "Authorize your first spend" })).toBeVisible({
      timeout: 10 * 60 * 1_000,
    });
    hashes.accountCreation = await readAccountCreationHash(page);
    console.log(`Committed account creation transaction: ${hashes.accountCreation}`);

    await page.getByRole("button", { name: "Authorize 100 CKB spend" }).click();
    await expect(page.getByRole("heading", { name: "Transaction submitted" })).toBeVisible({
      timeout: 2 * 60 * 1_000,
    });
    hashes.spend = await readDisplayedSpendHash(page);
    console.log(`Submitted spend transaction: ${hashes.spend}`);
    await expect(page.getByRole("heading", { name: "Spend committed" })).toBeVisible({
      timeout: 10 * 60 * 1_000,
    });
  } catch (error) {
    console.error(
      `Real-testnet flow stopped; preserve and inspect these public hashes: ${JSON.stringify(hashes)}`,
    );
    throw error;
  }
});
