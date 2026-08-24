import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const distDirectory = resolve(process.cwd(), "dist");
const forbiddenContent = [
  "CKB_PRIVKEY",
  "SignerCkbPrivateKey",
  "bootstrap-lib",
  "child_process",
  "state-exporter",
  "src/server",
];
const forbiddenModules = [
  /(^|\/)src\/server(\/|$)/,
  /(^|\/)tools\/deploy(\/|$)/,
  /(^|\/)bootstrap-lib(?:\.[cm]?[jt]s)?$/,
  /(^|\/)state-exporter(?:\.[cm]?[jt]s)?$/,
  /(^|\/)node:child_process$/,
];
const textExtensions = new Set([".css", ".html", ".js", ".json", ".map", ".txt"]);

function extension(path) {
  const index = path.lastIndexOf(".");
  return index === -1 ? "" : path.slice(index);
}

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await filesUnder(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

async function main() {
  if (!(await stat(distDirectory).catch(() => null))?.isDirectory()) {
    throw new Error("demo/dist is missing; run npm run build first");
  }
  const files = await filesUnder(distDirectory);
  const manifestPath = resolve(distDirectory, ".vite/manifest.json");
  const moduleGraphPath = resolve(distDirectory, ".vite/client-modules.json");
  for (const path of files) {
    if (path === manifestPath || path === moduleGraphPath) continue;
    if (!textExtensions.has(extension(path))) continue;
    const contents = await readFile(path, "utf8");
    for (const term of forbiddenContent) {
      if (contents.includes(term)) {
        throw new Error(`client bundle contains forbidden server term ${term} in ${path}`);
      }
    }
  }

  const manifestText = await readFile(manifestPath, "utf8").catch(() => {
    throw new Error("Vite client manifest is missing; run npm run build first");
  });
  const manifest = JSON.parse(manifestText);
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    throw new Error("Vite client manifest is malformed");
  }
  const manifestFiles = new Set();
  for (const [source, chunk] of Object.entries(manifest)) {
    const graphEntry = JSON.stringify({ source, chunk });
    if (forbiddenContent.some((term) => graphEntry.includes(term))) {
      throw new Error(`client module graph contains a server-only source: ${source}`);
    }
    if (typeof chunk === "object" && chunk !== null && "file" in chunk && typeof chunk.file === "string") {
      manifestFiles.add(chunk.file);
    }
  }

  const moduleGraphText = await readFile(moduleGraphPath, "utf8").catch(() => {
    throw new Error("client module graph is missing; run npm run build first");
  });
  const moduleGraph = JSON.parse(moduleGraphText);
  if (
    typeof moduleGraph !== "object" ||
    moduleGraph === null ||
    moduleGraph.version !== 1 ||
    !Array.isArray(moduleGraph.chunks) ||
    moduleGraph.chunks.length === 0
  ) {
    throw new Error("client module graph is malformed");
  }
  let foundClientEntry = false;
  const evidenceFiles = new Set();
  for (const chunk of moduleGraph.chunks) {
    if (
      typeof chunk !== "object" ||
      chunk === null ||
      typeof chunk.fileName !== "string" ||
      !Array.isArray(chunk.modules) ||
      !chunk.modules.every((moduleId) => typeof moduleId === "string")
    ) {
      throw new Error("client module graph is malformed");
    }
    evidenceFiles.add(chunk.fileName);
    for (const moduleId of chunk.modules) {
      if (moduleId.endsWith("src/client/main.tsx")) foundClientEntry = true;
      if (
        forbiddenContent.some((term) => moduleId.includes(term)) ||
        forbiddenModules.some((pattern) => pattern.test(moduleId))
      ) {
        throw new Error(`client module graph contains server-only module ${moduleId}`);
      }
    }
  }
  if (!foundClientEntry) {
    throw new Error("client module graph does not contain the browser entry module");
  }
  for (const file of manifestFiles) {
    if (!evidenceFiles.has(file)) {
      throw new Error(`client module graph has no evidence for manifest chunk ${file}`);
    }
  }
  console.log(
    `Client bundle boundary verified across ${files.length} files and ${moduleGraph.chunks.length} module-graph chunks`,
  );
}

await main();
