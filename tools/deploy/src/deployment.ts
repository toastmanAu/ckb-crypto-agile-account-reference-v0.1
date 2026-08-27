import { ALL_ARTIFACTS, PHASED_P256_ARTIFACTS } from "./plan.js";

export interface DeployedRecord {
  name: string;
  dataHash: string;
  hashType: "data2";
  txHash: string;
  index: number;
  capacityShannons: string;
}

export interface DeploymentManifest {
  schema_version: 1;
  network: "testnet";
  published: true;
  hash_type: "data2";
  note: string;
  artifacts: Record<string, DeployedRecord>;
}

export function parseDeploymentArgs(argv: string[]): {
  broadcast: boolean;
  selection: string[];
} {
  let broadcast = false;
  let all = false;
  let only: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--broadcast") {
      broadcast = true;
      continue;
    }
    if (argument === "--all") {
      all = true;
      continue;
    }
    if (argument === "--only") {
      if (only !== undefined) throw new Error("--only may be specified once");
      const name = argv[index + 1];
      if (name === undefined || name.startsWith("--")) {
        throw new Error("--only requires an artifact name");
      }
      only = name;
      index += 1;
      continue;
    }
    throw new Error(`unknown argument '${argument}'`);
  }

  if (all && only !== undefined) {
    throw new Error("cannot combine --all with --only");
  }
  if (only === undefined) {
    return {
      broadcast,
      selection: all ? [...ALL_ARTIFACTS] : [...PHASED_P256_ARTIFACTS],
    };
  }
  if (!ALL_ARTIFACTS.includes(only)) {
    throw new Error(`unknown artifact '${only}'`);
  }
  return { broadcast, selection: [only] };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deployedRecord(value: unknown, name: string): DeployedRecord {
  if (!isObject(value)
    || value.name !== name
    || typeof value.dataHash !== "string"
    || !/^0x[0-9a-f]{64}$/.test(value.dataHash)
    || value.hashType !== "data2"
    || typeof value.txHash !== "string"
    || !/^0x[0-9a-f]{64}$/.test(value.txHash)
    || !Number.isSafeInteger(value.index)
    || (value.index as number) < 0
    || typeof value.capacityShannons !== "string"
    || !/^[1-9][0-9]*$/.test(value.capacityShannons)
  ) {
    throw new Error(`existing deployment manifest has an invalid '${name}' record`);
  }
  return value as unknown as DeployedRecord;
}

function existingArtifacts(value: unknown): Record<string, DeployedRecord> {
  if (value === undefined) return {};
  if (!isObject(value)
    || value.schema_version !== 1
    || value.network !== "testnet"
    || value.published !== true
    || value.hash_type !== "data2"
    || typeof value.note !== "string"
    || !isObject(value.artifacts)
  ) {
    throw new Error("existing deployment manifest is malformed");
  }
  return Object.fromEntries(
    Object.entries(value.artifacts).map(([name, record]) => [name, deployedRecord(record, name)]),
  );
}

export function buildDeploymentManifest(
  existing: unknown,
  records: DeployedRecord[],
): DeploymentManifest {
  const artifacts = existingArtifacts(existing);
  for (const record of records) {
    artifacts[record.name] = deployedRecord(record, record.name);
  }
  return {
    schema_version: 1,
    network: "testnet",
    published: true,
    hash_type: "data2",
    note:
      "Outpoints recorded by tools/deploy. Each cell's on-chain data hash was " +
      "re-read and verified after commitment.",
    artifacts,
  };
}

export async function publishDeployment<T>(
  existing: unknown,
  cells: readonly T[],
  publish: (cell: T) => Promise<DeployedRecord>,
): Promise<DeploymentManifest> {
  const validated = buildDeploymentManifest(existing, []);
  const records: DeployedRecord[] = [];
  for (const cell of cells) records.push(await publish(cell));
  return buildDeploymentManifest(validated, records);
}
