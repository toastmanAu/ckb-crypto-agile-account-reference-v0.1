import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import {
  BootstrapRequestSchema,
  DeploymentManifestSchema,
  type BootstrapRequest,
  type DeploymentManifest,
} from "../shared/schemas.js";
import { CLIENT_ORIGIN, RP_ID } from "../shared/constants.js";
import { bytesFromHex, hexFromBytes } from "../shared/bytes.js";
import { ckbHash } from "../shared/protocol.js";
import { ApiError } from "./errors.js";

const TEMP_DIRECTORY_PREFIX = "ckb-passkey-state-";

export interface SpawnProcessOptions {
  cwd: string;
  shell: false;
  env: NodeJS.ProcessEnv;
}

export interface SpawnProcessResult {
  exitCode: number;
  stderr: string;
}

export interface ExporterDeps {
  repoRoot: string;
  deployment: DeploymentManifest;
  processEnv: NodeJS.ProcessEnv;
  makeTempDir(): Promise<string>;
  writeFile(
    path: string,
    data: string,
    options: { mode: number; flag: string },
  ): Promise<void>;
  spawnProcess(
    command: string,
    args: readonly string[],
    options: SpawnProcessOptions,
  ): Promise<SpawnProcessResult>;
  readFile(path: string): Promise<Uint8Array>;
  removeDir(path: string): Promise<void>;
}

function sanitizedEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(env).filter(([name]) => name.toUpperCase() !== "CKB_PRIVKEY"),
  );
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function accountConfiguration(request: BootstrapRequest, deployment: DeploymentManifest) {
  const keyId = hexFromBytes(ckbHash(bytesFromHex(request.publicKey)));
  const aux = `0x01${sha256Hex(RP_ID)}${sha256Hex(CLIENT_ORIGIN)}`;
  return {
    flags: 1,
    sequence: 0,
    spend_threshold: 1,
    rotate_threshold: 1,
    recovery_threshold: 1,
    recovery_since: 0,
    authenticators: [
      {
        slot: 0,
        algorithm_id: 1,
        capabilities: 7,
        weight: 1,
        verifier_hash_type: 0,
        verifier_abi: 1,
        verifier_code_hash: deployment.artifacts.verifier_p256.dataHash,
        key_id: keyId,
        aux,
      },
    ],
  };
}

function safeTemporaryDirectory(path: string): string {
  const resolved = resolve(path);
  if (
    dirname(resolved) !== resolve(tmpdir()) ||
    !basename(resolved).startsWith(TEMP_DIRECTORY_PREFIX)
  ) {
    throw new ApiError("BOOTSTRAP_FAILED", 500, "Account state export failed");
  }
  return resolved;
}

export async function exportAccountState(
  requestValue: BootstrapRequest,
  deps: ExporterDeps,
): Promise<Uint8Array> {
  const requestResult = BootstrapRequestSchema.safeParse(requestValue);
  if (!requestResult.success) {
    throw new ApiError("INVALID_REQUEST", 400, "Invalid account bootstrap request");
  }
  const deploymentResult = DeploymentManifestSchema.safeParse(deps.deployment);
  if (!deploymentResult.success) {
    throw new ApiError("DEPLOYMENT_INVALID", 500, "Testnet deployment is invalid");
  }

  let directory: string | undefined;
  try {
    directory = safeTemporaryDirectory(await deps.makeTempDir());
    const configPath = join(directory, "account.json");
    const outputPath = join(directory, "state.bin");
    const config = accountConfiguration(requestResult.data, deploymentResult.data);
    await deps.writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, {
      mode: 0o600,
      flag: "wx",
    });

    const result = await deps.spawnProcess(
      "cargo",
      [
        "run",
        "-q",
        "-p",
        "ckb-account-host",
        "--example",
        "export_account_state",
        "--",
        configPath,
        outputPath,
      ],
      {
        cwd: deps.repoRoot,
        shell: false,
        env: sanitizedEnvironment(deps.processEnv),
      },
    );
    if (result.exitCode !== 0) {
      throw new ApiError("BOOTSTRAP_FAILED", 500, "Account state export failed");
    }

    const output = await deps.readFile(outputPath);
    if (output.length === 0) {
      throw new ApiError("BOOTSTRAP_FAILED", 500, "Account state export failed");
    }
    return new Uint8Array(output);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError("BOOTSTRAP_FAILED", 500, "Account state export failed");
  } finally {
    if (directory !== undefined) {
      await deps.removeDir(directory);
    }
  }
}

async function spawnCargo(
  command: string,
  args: readonly string[],
  options: SpawnProcessOptions,
): Promise<SpawnProcessResult> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: options.shell,
      env: options.env,
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length < 16_384) stderr += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("close", (code) => {
      resolvePromise({ exitCode: code ?? 1, stderr: stderr.slice(0, 16_384) });
    });
  });
}

export function createExporterDeps(
  repoRoot: string,
  deployment: DeploymentManifest,
  processEnv: NodeJS.ProcessEnv = process.env,
): ExporterDeps {
  return {
    repoRoot,
    deployment,
    processEnv,
    async makeTempDir() {
      const directory = await mkdtemp(join(tmpdir(), TEMP_DIRECTORY_PREFIX));
      await chmod(directory, 0o700);
      return directory;
    },
    async writeFile(path, data, options) {
      await writeFile(path, data, options);
    },
    spawnProcess: spawnCargo,
    async readFile(path) {
      return readFile(path);
    },
    async removeDir(path) {
      await rm(path, { recursive: true, force: true });
    },
  };
}
