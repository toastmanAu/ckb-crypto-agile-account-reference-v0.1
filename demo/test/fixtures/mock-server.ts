import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isDeepStrictEqual } from "node:util";

import { ccc } from "@ckb-ccc/core";
import { z } from "zod";

import { bytesFromHex, hexFromBytes } from "../../src/shared/bytes.js";
import { CLIENT_ORIGIN } from "../../src/shared/constants.js";
import {
  TYPE_ID_CODE_HASH,
  validateAccount,
  validateDeployment,
} from "../../src/shared/manifests.js";
import { ckbHash } from "../../src/shared/protocol.js";
import {
  BootstrapRequestSchema,
  DemoStatusSchema,
  type AccountManifest,
  type DemoStatus,
} from "../../src/shared/schemas.js";
import { frontendVector } from "./frontend-v1.js";

const HOST = "127.0.0.1";
const PORT = 8790;
const CONTROL_TOKEN = "ckb-passkey-demo";
const FixtureControlSchema = z.object({
  confirmation: z.enum(["committed", "timeout"]).optional(),
  change: z.enum(["live", "missing"]).optional(),
}).strict();

const statusBase = DemoStatusSchema.parse({
  schemaVersion: 1,
  network: "testnet",
  origin: CLIENT_ORIGIN,
  rpId: "localhost",
  deploymentVerified: true,
  deployment: {
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
  },
  funderAddress:
    "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvcantfhvtwtyzgd4ssn0gjnjhkkl9q9lswhlggn",
  funderBalanceShannons: "19447999686508000",
  account: null,
} satisfies DemoStatus);
const typeIdArgs = `0x${"44".repeat(32)}`;
const accountId = ccc.Script.from({
  codeHash: TYPE_ID_CODE_HASH,
  hashType: "type",
  args: typeIdArgs,
}).hash();
const fixedAccount: AccountManifest = {
  schema_version: 1,
  network: "testnet",
  account_id: accountId,
  account_lock: {
    code_hash: statusBase.deployment.artifacts.account_lock.dataHash,
    hash_type: "data2",
    args: `0x01${accountId.slice(2)}`,
  },
  type_id_args: typeIdArgs,
  state_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 0 },
  asset_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 1 },
  state_bytes: (frontendVector.state.length - 2) / 2,
};
const verifiedAccount = validateAccount(
  fixedAccount,
  validateDeployment(statusBase.deployment),
);
const transactionHash = `0x${"aa".repeat(32)}`;
let account: AccountManifest | null = null;
let bootstrapRequest: ReturnType<typeof BootstrapRequestSchema.parse> | null = null;
let submittedTransaction: Record<string, unknown> | null = null;
let confirmationMode: "committed" | "timeout" = "committed";
let changeMode: "live" | "missing" = "live";
let sendTransactions = 0;
let confirmationChecks = 0;
let confirmationResponses = 0;
let changeScans = 0;

function sendJson(response: ServerResponse, value: unknown, statusCode = 200): void {
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(`${JSON.stringify(value)}\n`);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function rpcScript(script: ccc.Script): Record<string, string> {
  return {
    code_hash: script.codeHash,
    hash_type: script.hashType,
    args: script.args,
  };
}

function rpcOutput(
  capacity: bigint,
  type: ccc.Script | undefined = undefined,
): Record<string, unknown> {
  return {
    capacity: `0x${capacity.toString(16)}`,
    lock: rpcScript(verifiedAccount.accountLock),
    type: type === undefined ? null : rpcScript(type),
  };
}

function stateData(): string {
  if (bootstrapRequest === null) throw new Error("Fixture account is not bootstrapped");
  const bytes = bytesFromHex(frontendVector.state);
  bytes.set(ckbHash(bytesFromHex(bootstrapRequest.publicKey)), 80);
  return hexFromBytes(bytes);
}

function stateCell(): Record<string, unknown> {
  const data = stateData();
  return {
    output: rpcOutput(177n * 100_000_000n, verifiedAccount.stateType),
    data: { content: data, hash: hexFromBytes(ckbHash(bytesFromHex(data))) },
  };
}

function assetCell(): Record<string, unknown> {
  return {
    output: rpcOutput(200n * 100_000_000n),
    data: { content: "0x", hash: hexFromBytes(ckbHash(new Uint8Array())) },
  };
}

function changeCell(): Record<string, unknown> | undefined {
  const outputs = submittedTransaction?.outputs;
  const outputsData = submittedTransaction?.outputs_data;
  if (!Array.isArray(outputs) || !Array.isArray(outputsData)) return undefined;
  return {
    output: outputs[1],
    data: { content: outputsData[1], hash: hexFromBytes(ckbHash(new Uint8Array())) },
  };
}

function sameJson(left: unknown, right: unknown): boolean {
  return isDeepStrictEqual(left, right);
}

function requireFixture(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function validateSubmittedTransaction(value: unknown): asserts value is Record<string, unknown> {
  requireFixture(typeof value === "object" && value !== null, "Fixture transaction is malformed");
  const transaction = value as Record<string, unknown>;
  const inputs = transaction.inputs;
  const outputs = transaction.outputs;
  const outputsData = transaction.outputs_data;
  const cellDeps = transaction.cell_deps;
  const witnesses = transaction.witnesses;
  requireFixture(Array.isArray(inputs) && inputs.length === 1, "Fixture spend must have one input");
  requireFixture(
    sameJson((inputs[0] as Record<string, unknown>)?.previous_output, {
      tx_hash: fixedAccount.asset_out_point.tx_hash,
      index: "0x1",
    }),
    "Fixture spend input does not match the fixed AccountLock asset",
  );
  requireFixture(Array.isArray(outputs) && outputs.length === 2, "Fixture spend must have two outputs");
  requireFixture(
    (outputs[0] as Record<string, unknown>)?.capacity === "0x2540be400",
    "Fixture spend does not transfer exactly 100 CKB",
  );
  requireFixture(
    sameJson((outputs[1] as Record<string, unknown>)?.lock, rpcScript(verifiedAccount.accountLock)),
    "Fixture spend change does not use AccountLock",
  );
  requireFixture(
    Array.isArray(outputsData) && sameJson(outputsData, ["0x", "0x"]),
    "Fixture spend output data is not empty",
  );
  requireFixture(
    Array.isArray(cellDeps) && cellDeps.length === 3,
    "Fixture spend does not have three dependencies",
  );
  requireFixture(
    Array.isArray(witnesses) && witnesses.length === 1 && witnesses[0] !== "0x",
    "Fixture spend does not contain one finalized witness",
  );
}

async function handleRpc(payloadValue: unknown): Promise<Record<string, unknown>> {
  if (typeof payloadValue !== "object" || payloadValue === null) {
    throw new Error("Fixture JSON-RPC payload is malformed");
  }
  const payload = payloadValue as { id?: unknown; method?: unknown; params?: unknown };
  if (!Number.isInteger(payload.id) || typeof payload.method !== "string" || !Array.isArray(payload.params)) {
    throw new Error("Fixture JSON-RPC envelope is malformed");
  }
  let result: unknown;
  switch (payload.method) {
    case "get_live_cell": {
      const outPoint = payload.params[0] as { tx_hash?: unknown; index?: unknown };
      if (outPoint?.tx_hash === fixedAccount.state_out_point.tx_hash && outPoint.index === "0x0") {
        result = { status: "live", cell: stateCell() };
      } else if (outPoint?.tx_hash === fixedAccount.asset_out_point.tx_hash && outPoint.index === "0x1") {
        result = { status: "live", cell: assetCell() };
      } else if (outPoint?.tx_hash === transactionHash && outPoint.index === "0x1") {
        changeScans += 1;
        result = changeMode === "live"
          ? { status: "live", cell: changeCell() }
          : { status: "unknown" };
      } else {
        result = { status: "unknown" };
      }
      break;
    }
    case "get_cells": {
      const search = payload.params[0] as { script?: unknown; script_type?: unknown };
      if (search?.script_type !== "lock" || !sameJson(search.script, rpcScript(verifiedAccount.accountLock))) {
        throw new Error("Fixture indexer query does not target the AccountLock");
      }
      result = {
        last_cursor: "0x",
        objects: [
          {
            out_point: { tx_hash: fixedAccount.state_out_point.tx_hash, index: "0x0" },
            output: (stateCell().output),
            output_data: stateData(),
          },
          {
            out_point: { tx_hash: fixedAccount.asset_out_point.tx_hash, index: "0x1" },
            output: (assetCell().output),
            output_data: "0x",
          },
        ],
      };
      break;
    }
    case "send_transaction":
      validateSubmittedTransaction(payload.params[0]);
      if (submittedTransaction !== null) throw new Error("Fixture transaction was submitted more than once");
      submittedTransaction = payload.params[0];
      sendTransactions += 1;
      result = transactionHash;
      break;
    case "get_transaction":
      confirmationChecks += 1;
      if (payload.params[0] !== transactionHash || submittedTransaction === null) {
        result = null;
      } else if (confirmationMode === "timeout") {
        await new Promise((resolve) => setTimeout(resolve, 300));
        confirmationResponses += 1;
        result = {
          transaction: submittedTransaction,
          tx_status: { status: "pending" },
        };
      } else {
        await new Promise((resolve) => setTimeout(resolve, 200));
        result = {
          transaction: submittedTransaction,
          tx_status: {
            status: "committed",
            block_hash: `0x${"bb".repeat(32)}`,
            block_number: "0x1",
            tx_index: "0x0",
          },
        };
      }
      break;
    default:
      throw new Error(`Fixture JSON-RPC method is not allowed: ${payload.method}`);
  }
  return { jsonrpc: "2.0", id: payload.id, result, error: null };
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const path = new URL(request.url ?? "/", `http://${HOST}:${PORT}`).pathname;
  if (path.startsWith("/__test__/control")) {
    if (request.headers.host !== `${HOST}:${PORT}` || request.headers["x-test-control"] !== CONTROL_TOKEN) {
      sendJson(response, { error: { code: "BAD_ORIGIN", message: "Fixture control access denied" } }, 403);
      return;
    }
    if (request.method === "POST" && path === "/__test__/control/reset") {
      account = null;
      bootstrapRequest = null;
      submittedTransaction = null;
      confirmationMode = "committed";
      changeMode = "live";
      sendTransactions = 0;
      confirmationChecks = 0;
      confirmationResponses = 0;
      changeScans = 0;
      sendJson(response, { reset: true });
      return;
    }
    if (request.method === "POST" && path === "/__test__/control") {
      const parsed = FixtureControlSchema.safeParse(await readJson(request));
      if (!parsed.success) {
        sendJson(response, { error: { code: "INVALID_REQUEST", message: "Invalid fixture control" } }, 400);
        return;
      }
      confirmationMode = parsed.data.confirmation ?? confirmationMode;
      changeMode = parsed.data.change ?? changeMode;
      sendJson(response, { confirmation: confirmationMode, change: changeMode });
      return;
    }
    if (request.method === "GET" && path === "/__test__/control/events") {
      sendJson(response, { sendTransactions, confirmationChecks, confirmationResponses, changeScans });
      return;
    }
    sendJson(response, { error: { code: "INVALID_REQUEST", message: "Fixture control route not found" } }, 404);
    return;
  }
  if (request.headers.origin !== CLIENT_ORIGIN) {
    sendJson(response, { error: { code: "BAD_ORIGIN", message: "Fixture requests must come from the demo" } }, 403);
    return;
  }
  if (request.method === "GET" && path === "/api/status") {
    sendJson(response, DemoStatusSchema.parse({ ...statusBase, account }));
    return;
  }
  if (request.method === "GET" && path === "/api/account") {
    sendJson(response, account);
    return;
  }
  if (request.method === "POST" && path === "/api/account/bootstrap") {
    const result = BootstrapRequestSchema.safeParse(await readJson(request));
    if (!result.success) {
      sendJson(response, { error: { code: "INVALID_REQUEST", message: "Invalid fixture bootstrap request" } }, 400);
      return;
    }
    if (bootstrapRequest !== null && !sameJson(bootstrapRequest, result.data)) {
      sendJson(response, { error: { code: "ACCOUNT_MISMATCH", message: "Fixture account belongs to another passkey" } }, 409);
      return;
    }
    bootstrapRequest = result.data;
    account = fixedAccount;
    sendJson(response, account);
    return;
  }
  if (request.method === "POST" && path === "/__test__/rpc") {
    sendJson(response, await handleRpc(await readJson(request)));
    return;
  }
  sendJson(response, { error: { code: "INVALID_REQUEST", message: "Fixture route not found" } }, 404);
}

const server = createServer((request, response) => {
  void handle(request, response).catch((error: unknown) => {
    sendJson(response, {
      error: {
        code: "INTERNAL_ERROR",
        message: error instanceof Error ? error.message : "Fixture request failed",
      },
    }, 500);
  });
});
server.listen(PORT, HOST);

function close(): void {
  server.close(() => process.exit(0));
}

process.on("SIGINT", close);
process.on("SIGTERM", close);
