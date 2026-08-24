import type { AddressInfo } from "node:net";
import { request as httpRequest } from "node:http";

import { describe, expect, it } from "vitest";

import { createHttpServer } from "../../src/server/http.js";
import type { DemoService } from "../../src/server/service.js";
import { API_PORT, CLIENT_ORIGIN } from "../../src/shared/constants.js";
import type { AccountManifest, BootstrapRequest, DemoStatus } from "../../src/shared/schemas.js";

interface ResponseData {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function service(overrides: Partial<DemoService> = {}): DemoService {
  return {
    async status() {
      return { ok: true } as unknown as DemoStatus;
    },
    async account() {
      return null;
    },
    async bootstrap() {
      return { created: true } as unknown as AccountManifest;
    },
    ...overrides,
  };
}

async function withServer(
  demoService: DemoService,
  run: (port: number) => Promise<void>,
): Promise<void> {
  const server = createHttpServer(demoService);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    await run((server.address() as AddressInfo).port);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function call(
  port: number,
  path: string,
  options: {
    method?: string;
    origin?: string;
    host?: string;
    contentType?: string;
    body?: string;
  } = {},
): Promise<ResponseData> {
  return new Promise((resolve, reject) => {
    const body = options.body;
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: options.method ?? "GET",
        headers: {
          Host: options.host ?? `127.0.0.1:${API_PORT}`,
          Origin: options.origin ?? CLIENT_ORIGIN,
          ...(options.contentType ? { "Content-Type": options.contentType } : {}),
          ...(body === undefined ? {} : { "Content-Length": Buffer.byteLength(body) }),
        },
      },
      (response) => {
        let data = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => (data += chunk));
        response.on("end", () =>
          resolve({ status: response.statusCode ?? 0, headers: response.headers, body: data }),
        );
      },
    );
    req.once("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const validRequest: BootstrapRequest = {
  publicKey: `0x04${"11".repeat(64)}`,
  credentialId: "AQIDBA",
};

describe("localhost HTTP boundary", () => {
  it("serves exactly the status, account, and bootstrap routes as JSON", async () => {
    let received: BootstrapRequest | undefined;
    await withServer(
      service({
        async bootstrap(request) {
          received = request;
          return { created: true } as unknown as AccountManifest;
        },
      }),
      async (port) => {
        expect((await call(port, "/api/status")).status).toBe(200);
        expect((await call(port, "/api/account")).body).toBe("null\n");
        const created = await call(port, "/api/account/bootstrap", {
          method: "POST",
          contentType: "application/json",
          body: JSON.stringify(validRequest),
        });
        expect(created.status).toBe(200);
        expect(received).toEqual(validRequest);

        for (const path of [
          "/api/sign",
          "/api/reset",
          "/api/path",
          "/api/command",
          "/api/account/bootstrap/again",
        ]) {
          expect((await call(port, path)).status).toBe(404);
        }
      },
    );
  });

  it("sets restrictive response and origin headers without wildcard CORS", async () => {
    await withServer(service(), async (port) => {
      const response = await call(port, "/api/status");
      expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
      expect(response.headers["access-control-allow-origin"]).toBe(CLIENT_ORIGIN);
      expect(response.headers["access-control-allow-origin"]).not.toBe("*");
      expect(response.headers.vary).toBe("Origin");
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["x-content-type-options"]).toBe("nosniff");
      expect(response.headers["content-security-policy"]).toContain("default-src 'none'");
    });
  });

  it("rejects invalid host or origin before invoking the service", async () => {
    let calls = 0;
    await withServer(
      service({
        async status() {
          calls += 1;
          return {} as DemoStatus;
        },
      }),
      async (port) => {
        expect((await call(port, "/api/status", { host: `localhost:${API_PORT}` })).status).toBe(403);
        expect(
          (await call(port, "/api/status", { origin: "https://evil.example" })).status,
        ).toBe(403);
        expect(calls).toBe(0);
      },
    );
  });

  it("enforces methods, JSON content type, strict schemas, and the 16 KiB limit", async () => {
    await withServer(service(), async (port) => {
      expect((await call(port, "/api/status", { method: "POST" })).status).toBe(405);
      expect((await call(port, "/api/account/bootstrap", { method: "GET" })).status).toBe(405);
      expect(
        (
          await call(port, "/api/account/bootstrap", {
            method: "POST",
            contentType: "text/plain",
            body: JSON.stringify(validRequest),
          })
        ).status,
      ).toBe(415);
      expect(
        (
          await call(port, "/api/account/bootstrap", {
            method: "POST",
            contentType: "application/json",
            body: JSON.stringify({ ...validRequest, network: "mainnet" }),
          })
        ).status,
      ).toBe(400);
      expect(
        (
          await call(port, "/api/account/bootstrap", {
            method: "POST",
            contentType: "application/json",
            body: JSON.stringify({ padding: "x".repeat(17_000) }),
          })
        ).status,
      ).toBe(413);
    });
  });

  it("never returns internal error, stack, or key material", async () => {
    const secret = `0x${"ab".repeat(32)}`;
    await withServer(
      service({
        async status() {
          throw new Error(`failed with ${secret}\nSTACK_DETAIL`);
        },
      }),
      async (port) => {
        const response = await call(port, "/api/status");
        expect(response.status).toBe(500);
        expect(response.body).toContain("INTERNAL_ERROR");
        expect(response.body).not.toContain(secret);
        expect(response.body).not.toContain("STACK_DETAIL");
      },
    );
  });
});
