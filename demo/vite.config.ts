import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
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
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
});
