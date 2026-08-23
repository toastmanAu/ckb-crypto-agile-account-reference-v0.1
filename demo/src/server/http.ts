import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { CLIENT_ORIGIN } from "../shared/constants.js";
import { BootstrapRequestSchema } from "../shared/schemas.js";
import { ApiError, toSafeErrorBody } from "./errors.js";
import type { DemoService } from "./service.js";

const REQUIRED_HOST = "127.0.0.1:8787";
const BODY_LIMIT = 16 * 1024;

function setJsonHeaders(response: ServerResponse, allowOrigin: boolean): void {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Vary", "Origin");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  if (allowOrigin) response.setHeader("Access-Control-Allow-Origin", CLIENT_ORIGIN);
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
  allowOrigin = true,
): void {
  setJsonHeaders(response, allowOrigin);
  response.statusCode = status;
  response.end(`${JSON.stringify(value)}\n`);
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let length = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      length += chunk.length;
      if (length > BODY_LIMIT) {
        request.removeAllListeners("data");
        request.resume();
        reject(new ApiError("INVALID_REQUEST", 413, "Request body is too large"));
        return;
      }
      chunks.push(chunk);
    });
    request.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.once("error", reject);
  });
}

function methodNotAllowed(response: ServerResponse, allowed: string): void {
  response.setHeader("Allow", allowed);
  sendJson(response, 405, {
    error: { code: "INVALID_REQUEST", message: "Method not allowed" },
  });
}

async function handleRequest(
  service: DemoService,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const validOrigin = request.headers.origin === CLIENT_ORIGIN;
  if (request.headers.host !== REQUIRED_HOST || !validOrigin) {
    sendJson(
      response,
      403,
      { error: { code: "BAD_ORIGIN", message: "Request must come from the local demo" } },
      false,
    );
    return;
  }

  const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  if (path === "/api/status") {
    if (request.method !== "GET") return methodNotAllowed(response, "GET");
    sendJson(response, 200, await service.status());
    return;
  }
  if (path === "/api/account") {
    if (request.method !== "GET") return methodNotAllowed(response, "GET");
    sendJson(response, 200, await service.account());
    return;
  }
  if (path === "/api/account/bootstrap") {
    if (request.method !== "POST") return methodNotAllowed(response, "POST");
    if ((request.headers["content-type"] ?? "").split(";", 1)[0].trim() !== "application/json") {
      throw new ApiError("INVALID_REQUEST", 415, "Content-Type must be application/json");
    }
    const contentLength = Number(request.headers["content-length"] ?? 0);
    if (Number.isFinite(contentLength) && contentLength > BODY_LIMIT) {
      request.resume();
      throw new ApiError("INVALID_REQUEST", 413, "Request body is too large");
    }
    let value: unknown;
    try {
      value = JSON.parse(await readBody(request));
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError("INVALID_REQUEST", 400, "Request body must be valid JSON");
    }
    const parsed = BootstrapRequestSchema.safeParse(value);
    if (!parsed.success) {
      throw new ApiError("INVALID_REQUEST", 400, "Invalid account bootstrap request");
    }
    sendJson(response, 200, await service.bootstrap(parsed.data));
    return;
  }

  sendJson(response, 404, {
    error: { code: "INVALID_REQUEST", message: "Route not found" },
  });
}

export function createHttpServer(service: DemoService): Server {
  return createServer((request, response) => {
    void handleRequest(service, request, response).catch((error: unknown) => {
      const status = error instanceof ApiError ? error.status : 500;
      if (!response.headersSent) {
        sendJson(response, status, toSafeErrorBody(error));
      } else {
        response.end();
      }
    });
  });
}
