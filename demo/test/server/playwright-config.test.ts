import { describe, expect, it } from "vitest";

import config from "../../playwright.config.js";

describe("Playwright local-stack readiness", () => {
  it("waits for the local API status before starting browser tests", () => {
    expect(config.webServer).toMatchObject({
      url: "http://localhost:5173/api/status",
    });
  });
});
