import { expect, test, type Page } from "@playwright/test";
import { Secret, TOTP } from "otpauth";

/**
 * The M11 acceptance path, end to end through the real UI against a real panel:
 *
 *   sign in → enable 2FA → sign out → sign in with password and code →
 *   create a user → copy their subscription link → delete them.
 *
 * It is one test on purpose. Each step depends on the previous one's state, and splitting
 * them would only mean each part re-doing the setup of the parts before it.
 */

const username = process.env.E2E_USERNAME ?? "";
const password = process.env.E2E_PASSWORD ?? "";

// TOTP parameters the panel uses: SHA-1, six digits, thirty seconds (internal/auth/totp.go).
function codeFor(secret: string): string {
  return new TOTP({ secret: Secret.fromBase32(secret), algorithm: "SHA1", digits: 6, period: 30 }).generate();
}

/**
 * freshCode waits out the tail of a TOTP window. The panel refuses a code for a step it has
 * already accepted (replay protection), and a code generated in the last seconds of a window
 * can expire between being typed and being checked.
 */
async function freshCode(secret: string, usedStep?: number): Promise<{ code: string; step: number }> {
  for (;;) {
    const now = Date.now() / 1000;
    const step = Math.floor(now / 30);
    const remaining = 30 - (now % 30);
    if (remaining > 5 && step !== usedStep) return { code: codeFor(secret), step };
    await new Promise((resolve) => setTimeout(resolve, (remaining + 1) * 1000));
  }
}

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();
}

test.beforeAll(() => {
  if (!username || !password) throw new Error("E2E_USERNAME and E2E_PASSWORD must be set");
});

test("sign in with 2FA, create a user, copy the link, delete the user", async ({ page, context, browserName }) => {
  // Reading the clipboard back is how the copy is proven, and Chromium needs permission.
  if (browserName === "chromium") {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  }

  // --- password sign-in, the account has no second factor yet
  await signIn(page);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // --- enable 2FA
  await page.goto("/settings");
  await page.getByRole("button", { name: "Set up" }).click();
  const secretText = page.locator("code").filter({ hasText: /^[A-Z2-7]{16,}$/ });
  await expect(secretText).toBeVisible();
  const secret = (await secretText.textContent())?.trim() ?? "";
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);

  const first = await freshCode(secret);
  await page.getByLabel("Code").fill(first.code);
  await page.getByRole("button", { name: "Confirm" }).click();

  // Enabling 2FA invalidates earlier access tokens; the page must recover by itself and show
  // the new state rather than an error. This is the regression the smoke run first caught.
  await expect(page.getByText("on", { exact: true })).toBeVisible();
  await expect(page.getByText("invalid_token")).toHaveCount(0);

  // --- sign out, sign in again with password and code
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);

  await signIn(page);
  await expect(page.getByText("Enter the six-digit code")).toBeVisible();
  const second = await freshCode(secret, first.step);
  await page.getByLabel("Code").fill(second.code);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);

  // --- create a user
  const name = `smoke-${Date.now().toString(36)}`;
  await page.goto("/users");
  await page.getByRole("button", { name: "New user" }).click();
  await page.getByLabel("Username").fill(name);
  await page.getByLabel("Traffic limit").fill("10 GiB");
  await page.getByRole("button", { name: "Create" }).click();

  await expect(page).toHaveURL(/\/users\/\d+$/);
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await expect(page.getByText("0 B of 10.0 GiB")).toBeVisible();

  // --- copy the subscription link
  // exact: the copy button's "Copy subscription link" label would otherwise match too.
  const link = await page.getByLabel("Subscription link", { exact: true }).inputValue();
  expect(link).toMatch(/\/sub\/[A-Za-z0-9]+$/);

  await page.getByTestId("copy-subscription").click();
  await expect(page.getByTestId("copy-subscription")).toHaveText(/Copied/);
  if (browserName === "chromium") {
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied).toBe(link);
  }

  // --- delete the user
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("button", { name: "Delete user" }).click();
  await expect(page).toHaveURL(/\/users$/);
  await expect(page.getByRole("link", { name })).toHaveCount(0);

  // --- leave the account as it was found, so the test can run again
  await page.goto("/settings");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Turn off" }).click();
  await expect(page.getByText("off", { exact: true })).toBeVisible();
});
