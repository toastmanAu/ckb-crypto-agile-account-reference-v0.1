import { describe, expect, it } from "vitest";

import { CLIENT_ORIGIN, RP_ID } from "../../src/shared/constants.js";
import { ApiError, toSafeErrorBody } from "../../src/server/errors.js";
import { loadServerConfig } from "../../src/server/config.js";

const PRIVATE_KEY = `0x${"ab".repeat(32)}`;

describe("loadServerConfig", () => {
  it.each([
    undefined,
    "",
    "ab".repeat(32),
    `0x${"ab".repeat(31)}`,
    `0x${"gg".repeat(32)}`,
    `0x${"ab".repeat(33)}`,
  ])("rejects an unavailable or malformed private key without echoing it", (value) => {
    let error: unknown;
    try {
      loadServerConfig({ CKB_PRIVKEY: value });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ApiError);
    if (value) expect(String(error)).not.toContain(value);
    expect(toSafeErrorBody(error)).toEqual({
      error: {
        code: "KEY_UNAVAILABLE",
        message: "CKB_PRIVKEY is missing or invalid",
      },
    });
  });

  it("fixes the localhost security boundary and keeps the key non-enumerable", () => {
    const config = loadServerConfig({ CKB_PRIVKEY: PRIVATE_KEY });

    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(8787);
    expect(config.clientOrigin).toBe(CLIENT_ORIGIN);
    expect(config.rpId).toBe(RP_ID);
    expect(config.network).toBe("testnet");
    expect(config.privateKey).toBe(PRIVATE_KEY);
    expect(Object.keys(config)).not.toContain("privateKey");
    expect(JSON.stringify(config)).not.toContain(PRIVATE_KEY);
  });
});

describe("safe API errors", () => {
  it("returns an ApiError's stable public code and safe message", () => {
    expect(
      toSafeErrorBody(new ApiError("ACCOUNT_MISMATCH", 409, "Passkey does not match account")),
    ).toEqual({
      error: {
        code: "ACCOUNT_MISMATCH",
        message: "Passkey does not match account",
      },
    });
  });

  it("redacts messages and stacks from unexpected errors", () => {
    const secret = "0xprivate-material";
    const body = toSafeErrorBody(new Error(`RPC failed while using ${secret}`));

    expect(body).toEqual({
      error: { code: "INTERNAL_ERROR", message: "Unexpected local server error" },
    });
    expect(JSON.stringify(body)).not.toContain(secret);
  });
});
