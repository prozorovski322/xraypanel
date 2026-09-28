import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end smoke tests against a running panel and the built admin UI.
 *
 * They expect the panel to be up already (CI starts it with a bootstrap administrator whose
 * credentials arrive in E2E_USERNAME and E2E_PASSWORD) and serve the UI with `vite preview`,
 * which proxies /api to it. Browsers are installed by CI on the runner; nothing here downloads
 * them on a developer's machine.
 */
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  // The smoke run changes the one administrator's 2FA state, so tests must not overlap.
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run preview",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
