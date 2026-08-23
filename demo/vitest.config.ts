import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    setupFiles: [],
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
});
