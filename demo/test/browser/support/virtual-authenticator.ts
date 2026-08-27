import type { BrowserContext, CDPSession, Page } from "@playwright/test";

import { PASSKEY_STORAGE_KEY } from "../../../src/client/storage.js";
import { PasskeyRecordSchema } from "../../../src/shared/schemas.js";
import {
  RecoveryDocumentSchema,
  saveRecovery,
  type RealTestnetPaths,
  type RecoveryDocument,
} from "../../support/real-testnet-state.js";

export interface VirtualAuthenticatorHandle {
  authenticatorId: string;
  session: CDPSession;
}

export interface InstallVirtualAuthenticatorOptions {
  recovery?: RecoveryDocument | null;
  userVerified?: boolean;
  automaticPresence?: boolean;
}

export async function installVirtualAuthenticator(
  page: Page,
  options: InstallVirtualAuthenticatorOptions = {},
): Promise<VirtualAuthenticatorHandle> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  const { authenticatorId } = await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: options.userVerified ?? true,
      automaticPresenceSimulation: options.automaticPresence ?? true,
    },
  });
  for (const credential of options.recovery?.credentials ?? []) {
    await session.send("WebAuthn.addCredential", { authenticatorId, credential });
  }
  return { session, authenticatorId };
}

export async function captureAndPersistRecovery(
  page: Page,
  handle: VirtualAuthenticatorHandle,
  paths: RealTestnetPaths,
  now: Date,
): Promise<RecoveryDocument> {
  const serialized = await page.evaluate((key) => localStorage.getItem(key), PASSKEY_STORAGE_KEY);
  if (serialized === null) throw new Error("Passkey record is unavailable after registration");
  const passkey = PasskeyRecordSchema.parse(JSON.parse(serialized));
  const { credentials } = await handle.session.send("WebAuthn.getCredentials", {
    authenticatorId: handle.authenticatorId,
  });
  const recovery = RecoveryDocumentSchema.parse({
    schemaVersion: 1,
    network: "testnet",
    origin: "http://localhost:5173",
    rpId: "localhost",
    passkey,
    credentials,
    createdAt: now.toISOString(),
  });
  return saveRecovery(paths, recovery);
}

export async function addRecoveryInitScript(
  context: BrowserContext,
  recovery: RecoveryDocument,
): Promise<void> {
  await context.addInitScript(({ key, serialized }) => {
    const existing = localStorage.getItem(key);
    if (existing === null) localStorage.setItem(key, serialized);
    else if (existing !== serialized) throw new Error("Persistent passkey record conflicts with recovery");
  }, { key: PASSKEY_STORAGE_KEY, serialized: JSON.stringify(recovery.passkey) });
}
