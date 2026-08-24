import { fileURLToPath } from "node:url";
import { relative } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

import { API_ORIGIN, CLIENT_ORIGIN } from "./src/shared/constants.js";

function publicModuleId(moduleId: string): string {
  const normalized = moduleId.replaceAll("\\", "/");
  if (normalized.startsWith("\0")) return normalized;
  const withoutQuery = normalized.split("?", 1)[0]!;
  const local = relative(process.cwd(), withoutQuery).replaceAll("\\", "/");
  return local.startsWith("../") ? withoutQuery : local;
}

function clientModuleEvidence(): Plugin {
  return {
    name: "client-module-evidence",
    apply: "build",
    generateBundle(_outputOptions, bundle) {
      const chunks = Object.values(bundle)
        .filter((entry) => entry.type === "chunk")
        .map((chunk) => ({
          fileName: chunk.fileName,
          isEntry: chunk.isEntry,
          modules: Object.keys(chunk.modules).map(publicModuleId).sort(),
        }))
        .sort((left, right) => left.fileName.localeCompare(right.fileName));
      this.emitFile({
        type: "asset",
        fileName: ".vite/client-modules.json",
        source: `${JSON.stringify({ version: 1, chunks }, null, 2)}\n`,
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), clientModuleEvidence()],
  resolve: {
    alias: {
      "@ckb-ccc/core": fileURLToPath(
        new URL("./node_modules/@ckb-ccc/core/src/index.ts", import.meta.url),
      ),
    },
  },
  build: {
    manifest: true,
    rollupOptions: {
      output: {
        manualChunks(moduleId) {
          if (moduleId.includes("/node_modules/@ckb-ccc/")) return "ckb";
          if (moduleId.includes("/node_modules/react")) return "react";
          if (moduleId.includes("/node_modules/zod/")) return "validation";
          return undefined;
        },
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: API_ORIGIN,
        changeOrigin: true,
        headers: { Origin: CLIENT_ORIGIN },
      },
      ...(process.env.CKB_PASSKEY_BROWSER_FIXTURE === "1" ? {
        "/__test__": {
          target: API_ORIGIN,
          changeOrigin: true,
          headers: { Origin: CLIENT_ORIGIN },
        },
      } : {}),
    },
  },
});
