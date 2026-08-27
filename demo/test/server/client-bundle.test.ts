import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const checkerPath = resolve(process.cwd(), "scripts/check-client-bundle.mjs");
const temporaryRoots: string[] = [];

interface BundleFixtureOptions {
  asset?: string;
  manifestSource?: string;
  modules?: string[];
  omitModuleGraph?: boolean;
}

async function bundleFixture(options: BundleFixtureOptions = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "ckb-passkey-bundle-"));
  temporaryRoots.push(root);
  const dist = join(root, "dist");
  await mkdir(join(dist, ".vite"), { recursive: true });
  await mkdir(join(dist, "assets"), { recursive: true });
  await writeFile(join(dist, "index.html"), "<script src=/assets/main.js></script>");
  await writeFile(join(dist, "assets/main.js"), options.asset ?? "console.log('public client')");
  await writeFile(
    join(dist, ".vite/manifest.json"),
    JSON.stringify({
      [options.manifestSource ?? "src/client/main.tsx"]: {
        file: "assets/main.js",
        isEntry: true,
        src: options.manifestSource ?? "src/client/main.tsx",
      },
    }),
  );
  if (!options.omitModuleGraph) {
    await writeFile(
      join(dist, ".vite/client-modules.json"),
      JSON.stringify({
        version: 1,
        chunks: [
          {
            fileName: "assets/main.js",
            modules: options.modules ?? ["/repo/demo/src/client/main.tsx"],
          },
        ],
      }),
    );
  }
  return root;
}

async function runChecker(root: string): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(process.execPath, [checkerPath], { cwd: root });
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true })));
});

describe("built client boundary checker", () => {
  it("accepts safe asset, manifest, and Rollup module evidence", async () => {
    const root = await bundleFixture();

    await expect(runChecker(root)).resolves.toMatchObject({ stderr: "" });
  });

  it("fails closed when the Rollup module graph is missing", async () => {
    const root = await bundleFixture({ omitModuleGraph: true });

    await expect(runChecker(root)).rejects.toMatchObject({
      stderr: expect.stringContaining("client module graph is missing"),
    });
  });

  it("rejects a private-key term in a built asset", async () => {
    const root = await bundleFixture({ asset: "const name = 'CKB_PRIVKEY'" });

    await expect(runChecker(root)).rejects.toMatchObject({
      stderr: expect.stringContaining("forbidden server term CKB_PRIVKEY"),
    });
  });

  it("rejects server-only reachability in Rollup module evidence", async () => {
    const root = await bundleFixture({ modules: ["/repo/demo/src/server/config.ts"] });

    await expect(runChecker(root)).rejects.toMatchObject({
      stderr: expect.stringContaining("server-only module"),
    });
  });

  it("rejects a server entry in the Vite manifest", async () => {
    const root = await bundleFixture({ manifestSource: "src/server/index.ts" });

    await expect(runChecker(root)).rejects.toMatchObject({
      stderr: expect.stringContaining("server-only source"),
    });
  });
});
