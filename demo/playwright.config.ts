import { defineConfig } from "@playwright/test";

const realTestnetEnabled =
  process.env.CKB_PASSKEY_REAL_TESTNET_SPEC === "1" &&
  process.env.RUN_CKB_TESTNET === "1" &&
  /^0x[0-9a-fA-F]{64}$/.test(process.env.CKB_PRIVKEY ?? "");

export default defineConfig({
  testDir: "./test/browser",
  fullyParallel: false,
  workers: realTestnetEnabled ? 1 : undefined,
  use: {
    baseURL: "http://localhost:5173",
    browserName: "chromium",
  },
  webServer: {
    command: realTestnetEnabled ? "npm run dev" : "npm run dev:fixture",
    url: "http://localhost:5173",
    reuseExistingServer: false,
  },
});
