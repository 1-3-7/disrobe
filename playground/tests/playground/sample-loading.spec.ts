import { expect, test } from "@playwright/test";

declare global {
  interface Window {
    sampleAborted?: boolean;
  }
}

test.beforeEach(async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const fetch: typeof window.fetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, options?: RequestInit): Promise<Response> => {
      if (!String(input).includes("/samples/arith4.wasm")) return fetch(input, options);
      return new Promise((_resolve, reject): void => {
        options?.signal?.addEventListener("abort", (): void => {
          window.sampleAborted = true;
          reject(options.signal?.reason);
        }, { once: true });
      });
    };
  });
});

test("stopping a sample aborts its download", async ({ page }): Promise<void> => {
  await page.goto("./?mode=wasm-faithful-wat");
  await page.getByRole("button", { name: "Stop analysis", exact: true }).click();
  expect(await page.evaluate((): boolean => window.sampleAborted === true)).toBe(true);
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("a stalled sample times out and another mode still runs", async ({ page, isMobile }): Promise<void> => {
  await page.clock.install();
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByRole("button", { name: "Stop analysis", exact: true })).toBeVisible();
  await page.clock.fastForward(30_001);
  await expect(page.getByRole("alert")).toContainText("Loading the sample exceeded 30 seconds. Try again.");
  if (isMobile) await page.getByRole("button", { name: "Faithful WAT", exact: true }).click();
  await page.getByRole(isMobile ? "option" : "button", { name: "Detect & Peel", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
});
