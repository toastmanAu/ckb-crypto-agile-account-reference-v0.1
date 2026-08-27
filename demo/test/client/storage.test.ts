import { beforeEach, describe, expect, it } from "vitest";

import { CLIENT_ORIGIN, RP_ID } from "../../src/shared/constants.js";
import type { PasskeyRecord } from "../../src/shared/schemas.js";
import {
  PASSKEY_STORAGE_KEY,
  loadPasskeyRecord,
  savePasskeyRecord,
} from "../../src/client/storage.js";

const record: PasskeyRecord = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey:
    "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  keyId: "0x924617c0c1ca9afcaee0d49ae6ad8b282836c33b9e976d26c7f8b2abb5401893",
  rpId: RP_ID,
  origin: CLIENT_ORIGIN,
  createdAt: "2026-08-24T00:00:00.000Z",
};

describe("versioned public passkey storage", () => {
  beforeEach(() => localStorage.clear());

  it("round trips the strict public schema", () => {
    savePasskeyRecord(localStorage, record);

    expect(loadPasskeyRecord(localStorage)).toEqual(record);
    expect(JSON.parse(localStorage.getItem(PASSKEY_STORAGE_KEY)!)).toEqual(record);
  });

  it.each([
    ["malformed JSON", "{"],
    ["incompatible schema", JSON.stringify({ ...record, schemaVersion: 2 })],
    ["wrong RP", JSON.stringify({ ...record, rpId: "example.com" })],
    ["wrong origin", JSON.stringify({ ...record, origin: "https://example.com" })],
    ["unknown field", JSON.stringify({ ...record, label: "mine" })],
    ["private key field", JSON.stringify({ ...record, privateKey: "secret" })],
    ["environment key field", JSON.stringify({ ...record, CKB_PRIVKEY: "secret" })],
  ])("removes %s from active state", (_label, value) => {
    localStorage.setItem(PASSKEY_STORAGE_KEY, value);

    expect(loadPasskeyRecord(localStorage)).toBeNull();
    expect(localStorage.getItem(PASSKEY_STORAGE_KEY)).toBeNull();
  });

  it("refuses to save anything outside the public schema", () => {
    expect(() =>
      savePasskeyRecord(localStorage, { ...record, privateKey: "secret" } as PasskeyRecord),
    ).toThrow();
    expect(localStorage.getItem(PASSKEY_STORAGE_KEY)).toBeNull();
  });
});
