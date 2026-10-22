import { describe, expect, it, vi } from "vitest";

import {
  DemoApiError,
  createDemoApi,
} from "../../src/client/api.js";
import type {
  AccountManifest,
  DemoStatus,
  DeploymentManifest,
} from "../../src/shared/schemas.js";

const deployment: DeploymentManifest = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe",
      hashType: "data2",
      txHash: `0x${"11".repeat(32)}`,
      index: 0,
      capacityShannons: "3350900000000",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: "0x376a3e1bfefc57d63cff2e5d022283800fb6b5f014b5edac4be573d58a7b124a",
      hashType: "data2",
      txHash: `0x${"22".repeat(32)}`,
      index: 0,
      capacityShannons: "6218100000000",
    },
  },
};

const account: AccountManifest = {
  schema_version: 1,
  network: "testnet",
  account_id: "0x1c750c0786bc8646d418eddac78a33d0f9be2f24046a1681bd2562feeeb1a7bb",
  account_lock: {
    code_hash: deployment.artifacts.account_lock.dataHash,
    hash_type: "data2",
    args: "0x011c750c0786bc8646d418eddac78a33d0f9be2f24046a1681bd2562feeeb1a7bb",
  },
  type_id_args: `0x${"44".repeat(32)}`,
  state_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 0 },
  asset_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 1 },
  state_bytes: 177,
};

const status: DemoStatus = {
  schemaVersion: 1,
  network: "testnet",
  origin: "http://localhost:5173",
  rpId: "localhost",
  deploymentVerified: true,
  deployment,
  funderAddress: "ckt1-test-funder",
  funderBalanceShannons: "19447999686508",
  account,
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status: init.status ?? 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...init.headers,
    },
  });
}

describe("schema-validating localhost API client", () => {
  it("uses relative no-credential GET requests and validates status/account responses", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(status))
      .mockResolvedValueOnce(jsonResponse(account));
    const api = createDemoApi(fetcher);

    await expect(api.status()).resolves.toEqual(status);
    await expect(api.account()).resolves.toEqual(account);
    expect(fetcher).toHaveBeenNthCalledWith(1, "/api/status", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      cache: "no-store",
    });
    expect(fetcher).toHaveBeenNthCalledWith(2, "/api/account", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      cache: "no-store",
    });
  });

  it("posts only the strict public bootstrap request as JSON", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(account));
    const api = createDemoApi(fetcher);
    const request = {
      publicKey: `0x04${"11".repeat(64)}`,
      credentialId: "AQIDBA",
    };

    await expect(api.bootstrap(request)).resolves.toEqual(account);
    expect(fetcher).toHaveBeenCalledWith("/api/account/bootstrap", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      credentials: "omit",
      cache: "no-store",
      body: JSON.stringify(request),
    });
    await expect(
      api.bootstrap({ ...request, network: "mainnet" } as typeof request),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("turns validated API errors into typed safe errors", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "ACCOUNT_MISMATCH",
            message: "Existing account does not match this passkey",
          },
        },
        { status: 409 },
      ),
    );

    await expect(createDemoApi(fetcher).account()).rejects.toEqual(
      expect.objectContaining({
        name: "DemoApiError",
        code: "ACCOUNT_MISMATCH",
        status: 409,
        message: "Existing account does not match this passkey",
      }),
    );
  });

  it("never exposes malformed response bodies or network error details", async () => {
    const secret = `0x${"ab".repeat(32)}`;
    const malformed = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ stack: `internal ${secret}` }, { status: 500 }),
    );
    const offline = vi.fn<typeof fetch>().mockRejectedValue(new Error(`connect ${secret}`));

    for (const api of [createDemoApi(malformed), createDemoApi(offline)]) {
      const error = await api.status().catch((reason: unknown) => reason);
      expect(error).toBeInstanceOf(DemoApiError);
      expect(String(error)).not.toContain(secret);
      expect(error).toMatchObject({
        code: expect.stringMatching(/^(INVALID_RESPONSE|API_UNAVAILABLE)$/),
      });
    }
  });

  it("rejects successful responses with the wrong content type or schema", async () => {
    const wrongType = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(status), {
        headers: { "Content-Type": "text/plain" },
      }),
    );
    const wrongSchema = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ ...status, network: "mainnet" }),
    );

    await expect(createDemoApi(wrongType).status()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
    await expect(createDemoApi(wrongSchema).status()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });
});
