import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./test/browser",
  use: {
    baseURL: "http://localhost:5173",
    browserName: "chromium",
  },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
  },
});
