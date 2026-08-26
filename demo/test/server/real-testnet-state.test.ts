import { describe, expect, it } from "vitest";

import {
  RecoveryDocumentSchema,
  RunDocumentSchema,
  classifyPresence,
  credentialMatchesPasskey,
  decideNextAction,
} from "../support/real-testnet-state.js";

const passkey = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey: `0x04${"11".repeat(64)}`,
  keyId: `0x${"22".repeat(32)}`,
  rpId: "localhost",
  origin: "http://localhost:5173",
  createdAt: "2026-08-26T00:00:00.000Z",
};

const credential = {
  credentialId: "AQIDBA==",
  isResidentCredential: true,
  rpId: "localhost",
  privateKey: "AQIDBA==", // synthetic schema fixture, not a usable PKCS#8 key
  userHandle: "BQYHCA==",
  signCount: 0,
};

const recovery = {
  schemaVersion: 1,
  network: "testnet",
  origin: "http://localhost:5173",
  rpId: "localhost",
  passkey,
  credentials: [credential],
  createdAt: "2026-08-26T00:00:00.000Z",
};

describe("real-testnet recovery state", () => {
  it.each([
    [false, false, "fresh"],
    [false, true, "registered"],
    [true, true, "recoverable_account"],
    [true, false, "orphaned_account"],
  ] as const)("classifies manifest=%s recovery=%s as %s", (manifest, saved, expected) => {
    expect(classifyPresence({ manifestExists: manifest, recoveryExists: saved })).toBe(expected);
  });

  it("requires one localhost testnet credential matching the public passkey record", () => {
    expect(RecoveryDocumentSchema.parse(recovery)).toEqual(recovery);
    expect(credentialMatchesPasskey(credential, passkey)).toBe(true);
    expect(() => RecoveryDocumentSchema.parse({ ...recovery, origin: "https://example.com" }))
      .toThrow();
    expect(() => RecoveryDocumentSchema.parse({ ...recovery, credentials: [] })).toThrow();
  });

  it("accepts only public run stages and 32-byte transaction hashes", () => {
    expect(RunDocumentSchema.parse({
      schemaVersion: 1,
      stage: "account_committed",
      accountId: `0x${"33".repeat(32)}`,
      accountCreationHash: `0x${"44".repeat(32)}`,
      lastReconciledAt: "2026-08-26T00:00:00.000Z",
    }).stage).toBe("account_committed");
  });

  it.each([
    [{ disk: "fresh", visible: "create_passkey", runStage: undefined }, "register"],
    [{ disk: "registered", visible: "create_account", runStage: "registered" }, "bootstrap"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "registered" }, "reconcile_account"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "account_committed" }, "spend"],
    [{ disk: "recoverable_account", visible: "authorize_spend", runStage: "spend_submitted" }, "reconcile_spend"],
    [{ disk: "orphaned_account", visible: "blocked", runStage: undefined }, "block"],
  ] as const)("chooses one non-duplicating action for %o", (input, expected) => {
    expect(decideNextAction(input)).toBe(expected);
  });
});
