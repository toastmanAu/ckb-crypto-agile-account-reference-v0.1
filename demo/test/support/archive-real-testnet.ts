import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { archiveRealTestnetState, createRealTestnetPaths } from "./real-testnet-state.js";

const demoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = resolve(demoRoot, "..");
const result = await archiveRealTestnetState(createRealTestnetPaths(repoRoot), new Date());

console.log(`Archived local testnet state at ${result.archiveDir}`);
console.log(`Account ${result.summary.accountId ?? "not created"}`);
console.log(`Account creation ${result.summary.accountCreationHash ?? "not submitted"}`);
console.log(`Credential available ${result.summary.credentialAvailable ? "yes" : "no"}`);
