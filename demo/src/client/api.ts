import type { z } from "zod";

import {
  AccountManifestSchema,
  ApiErrorBodySchema,
  BootstrapRequestSchema,
  DemoStatusSchema,
  type AccountManifest,
  type ApiErrorBody,
  type BootstrapRequest,
  type DemoStatus,
} from "../shared/schemas.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

export type DemoApiErrorCode =
  | ApiErrorBody["error"]["code"]
  | "API_UNAVAILABLE"
  | "INVALID_RESPONSE";

export class DemoApiError extends Error {
  constructor(
    public readonly code: DemoApiErrorCode,
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "DemoApiError";
  }
}

export interface DemoApi {
  status(): Promise<DemoStatus>;
  account(): Promise<AccountManifest | null>;
  bootstrap(request: BootstrapRequest): Promise<AccountManifest>;
}

interface RequestOptions {
  method: "GET" | "POST";
  body?: string;
}

function invalidResponse(): DemoApiError {
  return new DemoApiError(
    "INVALID_RESPONSE",
    "Local API returned an invalid response",
  );
}

async function requestJson<T>(
  fetcher: typeof fetch,
  path: string,
  options: RequestOptions,
  schema: z.ZodType<T>,
): Promise<T> {
  let response: Response;
  try {
    response = await fetcher(path, {
      method: options.method,
      headers: options.body === undefined
        ? { Accept: "application/json" }
        : {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
      credentials: "omit",
      cache: "no-store",
      ...(options.body === undefined ? {} : { body: options.body }),
    });
  } catch {
    throw new DemoApiError(
      "API_UNAVAILABLE",
      "Local API is unavailable",
    );
  }

  if (response.headers.get("content-type") !== JSON_CONTENT_TYPE) {
    throw invalidResponse();
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw invalidResponse();
  }
  if (!response.ok) {
    const errorResult = ApiErrorBodySchema.safeParse(value);
    if (!errorResult.success) {
      throw invalidResponse();
    }
    throw new DemoApiError(
      errorResult.data.error.code,
      errorResult.data.error.message,
      response.status,
    );
  }
  const result = schema.safeParse(value);
  if (!result.success) {
    throw invalidResponse();
  }
  return result.data;
}

export function createDemoApi(fetcher: typeof fetch = globalThis.fetch): DemoApi {
  return {
    status() {
      return requestJson(fetcher, "/api/status", { method: "GET" }, DemoStatusSchema);
    },
    account() {
      return requestJson(
        fetcher,
        "/api/account",
        { method: "GET" },
        AccountManifestSchema.nullable(),
      );
    },
    bootstrap(requestValue) {
      const result = BootstrapRequestSchema.safeParse(requestValue);
      if (!result.success) {
        return Promise.reject(
          new DemoApiError("INVALID_REQUEST", "Invalid account bootstrap request"),
        );
      }
      return requestJson(
        fetcher,
        "/api/account/bootstrap",
        { method: "POST", body: JSON.stringify(result.data) },
        AccountManifestSchema,
      );
    },
  };
}
