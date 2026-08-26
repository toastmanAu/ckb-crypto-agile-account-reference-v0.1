import { resolve } from "node:path";
import { z } from "zod";

import { PasskeyRecordSchema } from "../../src/shared/schemas.js";

const HASH32 = /^0x[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const CdpCredentialSchema = z.object({
  credentialId: z.string().regex(BASE64),
  isResidentCredential: z.literal(true),
  rpId: z.literal("localhost"),
  privateKey: z.string().min(1).regex(BASE64),
  userHandle: z.string().regex(BASE64).optional(),
  signCount: z.number().int().nonnegative(),
  largeBlob: z.string().regex(BASE64).optional(),
  backupEligibility: z.boolean().optional(),
  backupState: z.boolean().optional(),
  userName: z.string().optional(),
  userDisplayName: z.string().optional(),
}).strict();

export const RecoveryDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  network: z.literal("testnet"),
  origin: z.literal("http://localhost:5173"),
  rpId: z.literal("localhost"),
  passkey: PasskeyRecordSchema,
  credentials: z.tuple([CdpCredentialSchema]),
  createdAt: z.string().datetime({ offset: true }),
}).strict().superRefine((value, context) => {
  if (!credentialMatchesPasskey(value.credentials[0], value.passkey)) {
    context.addIssue({ code: "custom", message: "credential ID does not match passkey record" });
  }
});

export const RunDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  stage: z.enum(["registered", "account_committed", "spend_submitted", "spend_committed"]),
  accountId: z.string().regex(HASH32).optional(),
  accountCreationHash: z.string().regex(HASH32).optional(),
  spendHash: z.string().regex(HASH32).optional(),
  lastReconciledAt: z.string().datetime({ offset: true }),
}).strict();

export type RecoveryDocument = z.infer<typeof RecoveryDocumentSchema>;
export type RunDocument = z.infer<typeof RunDocumentSchema>;
export type DiskState = "fresh" | "registered" | "recoverable_account" | "orphaned_account";
export type VisibleStage = "create_passkey" | "create_account" | "authorize_spend" | "submitted" | "committed" | "blocked";
export type NextAction = "register" | "bootstrap" | "reconcile_account" | "spend" | "reconcile_spend" | "complete" | "block";

export interface RealTestnetPaths {
  rootDir: string;
  activeDir: string;
  profileDir: string;
  recoveryPath: string;
  runPath: string;
  archivesDir: string;
  manifestPath: string;
}

export function createRealTestnetPaths(repoRoot: string): RealTestnetPaths {
  const rootDir = resolve(repoRoot, "demo/.local/real-testnet");
  const activeDir = resolve(rootDir, "active");
  return {
    rootDir,
    activeDir,
    profileDir: resolve(activeDir, "profile"),
    recoveryPath: resolve(activeDir, "recovery.json"),
    runPath: resolve(activeDir, "run.json"),
    archivesDir: resolve(rootDir, "archives"),
    manifestPath: resolve(repoRoot, "deploy/testnet-account.json"),
  };
}

export function credentialMatchesPasskey(
  credential: Pick<z.infer<typeof CdpCredentialSchema>, "credentialId">,
  passkey: Pick<z.infer<typeof PasskeyRecordSchema>, "credentialId">,
): boolean {
  return Buffer.from(credential.credentialId, "base64")
    .equals(Buffer.from(passkey.credentialId, "base64url"));
}

export function classifyPresence(input: { manifestExists: boolean; recoveryExists: boolean }): DiskState {
  if (input.manifestExists) return input.recoveryExists ? "recoverable_account" : "orphaned_account";
  return input.recoveryExists ? "registered" : "fresh";
}

export function decideNextAction(input: {
  disk: DiskState;
  visible: VisibleStage;
  runStage?: RunDocument["stage"];
}): NextAction {
  if (input.disk === "orphaned_account") return "block";
  if (input.disk === "fresh" && input.runStage !== undefined) return "block";
  if (input.runStage === "account_committed" && input.disk !== "recoverable_account") return "block";
  if (input.runStage === "spend_committed") {
    return input.disk === "recoverable_account" ? "complete" : "block";
  }
  if (input.runStage === "spend_submitted") {
    return input.disk === "recoverable_account" ? "reconcile_spend" : "block";
  }
  if (input.visible === "blocked" || input.visible === "submitted" || input.visible === "committed") {
    return "block";
  }
  if (input.disk === "fresh" && input.visible === "create_passkey") return "register";
  if (input.disk === "registered" && input.visible === "create_account") return "bootstrap";
  if (
    input.disk === "recoverable_account" &&
    input.visible === "authorize_spend" &&
    (input.runStage === undefined || input.runStage === "registered")
  ) return "reconcile_account";
  if (input.disk === "recoverable_account" && input.visible === "authorize_spend") return "spend";
  return "block";
}
