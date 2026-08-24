import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const distDirectory = resolve(process.cwd(), "dist");
const forbidden = [
  "CKB_PRIVKEY",
  "SignerCkbPrivateKey",
  "bootstrap-lib",
  "child_process",
  "state-exporter",
  "src/server",
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
  for (const path of files) {
    if (!textExtensions.has(extension(path))) continue;
    const contents = await readFile(path, "utf8");
    for (const term of forbidden) {
      if (contents.includes(term)) {
        throw new Error(`client bundle contains forbidden server term ${term} in ${path}`);
      }
    }
  }

  const manifestPath = resolve(distDirectory, ".vite/manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  for (const [source, chunk] of Object.entries(manifest)) {
    const graphEntry = JSON.stringify({ source, chunk });
    if (forbidden.some((term) => graphEntry.includes(term))) {
      throw new Error(`client module graph contains a server-only source: ${source}`);
    }
  }
  console.log(`Client bundle boundary verified across ${files.length} files`);
}

await main();
