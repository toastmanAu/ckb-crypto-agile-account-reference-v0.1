import { ccc } from "@ckb-ccc/core";
import {
  chromium,
  expect,
  test,
  type BrowserContext,
  type Page,
} from "@playwright/test";
import { lstat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createRealTestnetPaths,
  decideNextAction,
  ensurePrivateStateDirectories,
  loadDiskState,
  loadRecovery,
  loadRun,
  mergeRun,
  saveRun,
  type RealTestnetPaths,
  type RunDocument,
} from "../support/real-testnet-state.js";
import { readAccountManifest } from "./support/real-testnet-account.js";
import { visibleStage } from "./support/real-testnet-stage.js";
import {
  addRecoveryInitScript,
  captureAndPersistRecovery,
  installVirtualAuthenticator,
  type VirtualAuthenticatorHandle,
} from "./support/virtual-authenticator.js";

const privateKeyIsValid = /^0x[0-9a-fA-F]{64}$/.test(process.env.CKB_PRIVKEY ?? "");
const realTestnetEnabled =
  process.env.CKB_PASSKEY_REAL_TESTNET_SPEC === "1"
  && process.env.RUN_CKB_TESTNET === "1"
  && privateKeyIsValid;

test.skip(
  !realTestnetEnabled,
  "real testnet browser coverage requires its internal marker, RUN_CKB_TESTNET=1, and a valid CKB_PRIVKEY",
);
test.describe.configure({ mode: "serial" });

const ACCOUNT_STATE_BYTES = 177;
const ACCOUNT_STATE_CAPACITY_CKB = 316;
const ACCOUNT_ASSET_CAPACITY_CKB = 200;
const BOOTSTRAP_FEE_RESERVE_CKB = 1;
const BROWSER_ACTION_TIMEOUT_MS = 30_000;
const ACCOUNT_MANIFEST_TIMEOUT_MS = 30_000;
const FAILURE_DIAGNOSTIC_TIMEOUT_MS = 1_000;
const demoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = resolve(demoRoot, "..");
const paths = createRealTestnetPaths(repoRoot);

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

function asTransactionHash(value: string): `0x${string}` {
  if (!/^0x[0-9a-f]{64}$/.test(value)) {
    throw new Error("Public transaction hash is malformed");
  }
  return value as `0x${string}`;
}

async function readDisplayedSpendHash(page: Page): Promise<`0x${string}`> {
  const label = await page.getByLabel(/Transaction hash 0x/).getAttribute("aria-label");
  const match = label?.match(/0x[0-9a-f]{64}/i);
  if (match === undefined || match === null) {
    throw new Error("Submitted receipt did not expose a transaction hash");
  }
  return asTransactionHash(match[0].toLowerCase());
}

export async function reconcileKnownSpend(txHash: `0x${string}`): Promise<void> {
  const client = new ccc.ClientPublicTestnet();
  const response = await client.getTransaction(txHash);
  if (response === undefined) throw new Error(`Known spend ${txHash} is unavailable`);
  if (response.status === "rejected") throw new Error(`Known spend ${txHash} was rejected`);
  if (response.status !== "committed") await client.waitTransaction(txHash, 0, 300_000);
  const change = await client.getCellLive({ txHash, index: 1 }, true, true);
  if (change === undefined) {
    throw new Error(`Known spend ${txHash} has no live AccountLock change`);
  }
}

async function bootstrapAccount(
  page: Page,
  statePaths: RealTestnetPaths,
  run: RunDocument | null,
): Promise<RunDocument> {
  const disk = await loadDiskState(statePaths);
  if (disk.kind !== "registered" || disk.recovery === null) {
    throw new Error("Bootstrap requires a re-read, persisted recovery and no account manifest");
  }
  if (await visibleStage(page) !== "create_account") {
    throw new Error("Bootstrap stage changed before account creation; refusing mutation");
  }
  const verifiedRecovery = await loadRecovery(statePaths);
  if (verifiedRecovery === null) {
    throw new Error("Bootstrap requires a durably verified recovery document");
  }
  if (run === null) {
    run = await saveRun(statePaths, {
      schemaVersion: 1,
      stage: "registered",
      lastReconciledAt: new Date().toISOString(),
    });
  }
  if (run.stage !== "registered") throw new Error("Bootstrap requires registered run state");

  printCapacityPlan();
  await page.getByRole("button", { name: "Create testnet account" }).click();
  await expect(page.getByRole("heading", { name: "Authorize your first spend" }))
    .toBeVisible({ timeout: 10 * 60 * 1_000 });
  const manifest = await readAccountManifest(page, ACCOUNT_MANIFEST_TIMEOUT_MS);
  const next = mergeRun(run, {
    schemaVersion: 1,
    stage: "account_committed",
    accountId: manifest.account_id,
    accountCreationHash: manifest.state_out_point.tx_hash,
    lastReconciledAt: new Date().toISOString(),
  });
  const saved = await saveRun(statePaths, next);
  console.log(`Committed account creation transaction: ${saved.accountCreationHash}`);
  return saved;
}

async function submitAndCommitSpend(
  page: Page,
  statePaths: RealTestnetPaths,
  run: RunDocument | null,
): Promise<RunDocument> {
  const persistedRun = await loadRun(statePaths);
  if (persistedRun?.spendHash) {
    await reconcileKnownSpend(asTransactionHash(persistedRun.spendHash));
    return saveRun(statePaths, mergeRun(persistedRun, {
      ...persistedRun,
      stage: "spend_committed",
      lastReconciledAt: new Date().toISOString(),
    }));
  }
  if (
    persistedRun?.stage !== "account_committed"
    || run?.stage !== "account_committed"
    || persistedRun.accountCreationHash !== run.accountCreationHash
  ) {
    throw new Error("Spend requires re-read committed account state");
  }
  const disk = await loadDiskState(statePaths);
  if (disk.kind !== "recoverable_account") {
    throw new Error("Spend requires a recoverable active account");
  }
  const manifest = await readAccountManifest(page, ACCOUNT_MANIFEST_TIMEOUT_MS);
  if (
    manifest.account_id !== persistedRun.accountId
    || manifest.state_out_point.tx_hash !== persistedRun.accountCreationHash
  ) {
    throw new Error("Active account manifest conflicts with persisted public run metadata");
  }
  const originalAsset = {
    txHash: manifest.asset_out_point.tx_hash,
    index: manifest.asset_out_point.index,
  } as const;
  const client = new ccc.ClientPublicTestnet();
  if (await client.getCellLive(originalAsset, true, true) === undefined) {
    throw new Error(
      `Account asset ${originalAsset.txHash}:${originalAsset.index} is dead and no spend hash was preserved; manual read-only reconciliation is required`,
    );
  }
  if (await visibleStage(page) !== "authorize_spend") {
    throw new Error("Spend stage changed before authorization; refusing mutation");
  }

  const authorize = page.getByRole("button", { name: "Authorize 100 CKB spend" });
  await expect(authorize).toBeEnabled({ timeout: 2 * 60 * 1_000 });
  if (await page.getByRole("alert").first().isVisible()) {
    throw new Error("Spend preparation is blocked; refusing authorization");
  }
  await authorize.click();
  await expect(page.getByRole("heading", { name: "Transaction submitted" }))
    .toBeVisible({ timeout: 2 * 60 * 1_000 });
  const spendHash = await readDisplayedSpendHash(page);
  const submitted = mergeRun(persistedRun, {
    ...persistedRun,
    schemaVersion: 1,
    stage: "spend_submitted",
    spendHash,
    lastReconciledAt: new Date().toISOString(),
  });
  const savedSubmitted = await saveRun(statePaths, submitted);
  console.log(`Submitted spend transaction: ${savedSubmitted.spendHash}`);
  await expect(page.getByRole("heading", { name: "Spend committed" }))
    .toBeVisible({ timeout: 10 * 60 * 1_000 });
  const committed = mergeRun(savedSubmitted, {
    ...savedSubmitted,
    stage: "spend_committed",
    lastReconciledAt: new Date().toISOString(),
  });
  return saveRun(statePaths, committed);
}

async function explainBlockedAccount(page: Page): Promise<never> {
  const manifest = await readAccountManifest(page, ACCOUNT_MANIFEST_TIMEOUT_MS);
  const outPoint = {
    txHash: manifest.asset_out_point.tx_hash,
    index: manifest.asset_out_point.index,
  } as const;
  const client = new ccc.ClientPublicTestnet();
  const live = await client.getCellLive(outPoint, true, true);
  if (live === undefined) {
    throw new Error(
      `Account asset ${outPoint.txHash}:${outPoint.index} is dead and no spend hash was preserved; manual read-only reconciliation is required`,
    );
  }
  throw new Error(
    `UI blocked while account asset ${outPoint.txHash}:${outPoint.index} remains live; refusing authorization`,
  );
}

async function executeResumableFlow(
  page: Page,
  authenticator: VirtualAuthenticatorHandle,
  statePaths: RealTestnetPaths,
  initialRun: RunDocument | null,
): Promise<void> {
  let run = initialRun;
  for (let transition = 0; transition < 4; transition += 1) {
    if (!run?.spendHash) run = await loadRun(statePaths);
    if (run?.spendHash) {
      await reconcileKnownSpend(asTransactionHash(run.spendHash));
      run = mergeRun(run, {
        ...run,
        stage: "spend_committed",
        lastReconciledAt: new Date().toISOString(),
      });
      await saveRun(statePaths, run);
      return;
    }

    const currentDisk = await loadDiskState(statePaths);
    const stage = await visibleStage(page);
    const action = decideNextAction({
      disk: currentDisk.kind,
      visible: stage,
      runStage: run?.stage,
    });

    if (action === "register") {
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
      const saved = await captureAndPersistRecovery(
        page,
        authenticator,
        statePaths,
        new Date(),
      );
      const verified = await loadRecovery(statePaths);
      if (verified?.passkey.credentialId !== saved.passkey.credentialId) {
        throw new Error("Persisted recovery could not be verified");
      }
      run = await saveRun(statePaths, {
        schemaVersion: 1,
        stage: "registered",
        lastReconciledAt: new Date().toISOString(),
      });
      continue;
    }
    if (action === "bootstrap") {
      run = await bootstrapAccount(page, statePaths, run);
      continue;
    }
    if (action === "reconcile_account") {
      const manifest = await readAccountManifest(page, ACCOUNT_MANIFEST_TIMEOUT_MS);
      run = await saveRun(statePaths, mergeRun(run, {
        schemaVersion: 1,
        stage: "account_committed",
        accountId: manifest.account_id,
        accountCreationHash: manifest.state_out_point.tx_hash,
        lastReconciledAt: new Date().toISOString(),
      }));
      continue;
    }
    if (action === "spend") {
      await submitAndCommitSpend(page, statePaths, run);
      return;
    }
    if (action === "complete") return;
    if (action === "block" && currentDisk.kind === "recoverable_account") {
      await explainBlockedAccount(page);
    }
    throw new Error(`Refusing unsafe real-testnet transition: ${action}`);
  }
  throw new Error("Real-testnet state did not converge within four transitions");
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function safeFailureSummary(
  page: Page | null,
  statePaths: RealTestnetPaths,
  lifecycleStage: string,
): Promise<string> {
  const run = await loadRun(statePaths).catch(() => null);
  const disk = await loadDiskState(statePaths).then((value) => value.kind).catch(() => "unreadable");
  const heading = page === null
    ? null
    : await page.locator("main").getByRole("heading").first()
      .textContent({ timeout: FAILURE_DIAGNOSTIC_TIMEOUT_MS }).catch(() => null);
  const alert = page === null
    ? null
    : await page.getByRole("alert").first()
      .textContent({ timeout: FAILURE_DIAGNOSTIC_TIMEOUT_MS }).catch(() => null);
  const manifest = page === null
    ? null
    : await readAccountManifest(page, FAILURE_DIAGNOSTIC_TIMEOUT_MS).catch(() => null);
  const manifestPreserved = await pathExists(statePaths.manifestPath).catch(() => false);
  const recoveryPreserved = await pathExists(statePaths.recoveryPath).catch(() => false);
  const profilePreserved = await pathExists(statePaths.profileDir).catch(() => false);
  const runPreserved = await pathExists(statePaths.runPath).catch(() => false);
  const nextAction = disk === "orphaned_account"
    ? "archive"
    : run?.spendHash
      ? "reconcile known spend"
      : recoveryPreserved
        ? "resume"
        : "inspect before restarting registration";
  return JSON.stringify({
    lifecycleStage,
    disk,
    heading: heading?.trim() || null,
    alert: alert?.trim() || null,
    accountCreationHash: run?.accountCreationHash ?? null,
    spendHash: run?.spendHash ?? null,
    accountId: manifest?.account_id ?? run?.accountId ?? null,
    assetOutPoint: manifest?.asset_out_point ?? null,
    manifestPreserved,
    recoveryPreserved,
    profilePreserved,
    runPreserved,
    nextAction,
  });
}

test("completes or resumes the passkey account and fixed spend on CKB testnet", async () => {
  test.setTimeout(20 * 60 * 1_000);
  let context: BrowserContext | null = null;
  let page: Page | null = null;
  let lifecycleStage = "classify local state";

  try {
    await ensurePrivateStateDirectories(paths);
    const disk = await loadDiskState(paths);
    if (disk.kind === "orphaned_account") {
      throw new Error("Active account manifest has no recoverable passkey; archive it before a funded run");
    }
    const run = await loadRun(paths);

    lifecycleStage = "launch persistent browser";
    context = await chromium.launchPersistentContext(paths.profileDir, {
      baseURL: "http://localhost:5173",
      headless: true,
    });
    page = context.pages()[0] ?? await context.newPage();
    page.setDefaultTimeout(BROWSER_ACTION_TIMEOUT_MS);
    page.setDefaultNavigationTimeout(BROWSER_ACTION_TIMEOUT_MS);

    if (disk.recovery) await addRecoveryInitScript(context, disk.recovery);
    lifecycleStage = disk.recovery ? "restore virtual credential" : "install virtual authenticator";
    const authenticator = await installVirtualAuthenticator(page, { recovery: disk.recovery });

    lifecycleStage = "load application";
    await page.goto("/");
    lifecycleStage = "settle application stage";
    await visibleStage(page);
    lifecycleStage = "execute resumable flow";
    await executeResumableFlow(page, authenticator, paths, run);
  } catch {
    console.error(await safeFailureSummary(page, paths, lifecycleStage));
    throw new Error("Real-testnet flow stopped safely; inspect the preceding public failure summary");
  } finally {
    await context?.close();
  }
});
