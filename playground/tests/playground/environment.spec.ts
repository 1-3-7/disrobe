import { expect, test } from "@playwright/test";

test("theme controls work when preference storage is unavailable", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    Object.defineProperty(window, "localStorage", { get: (): never => { throw new DOMException("Storage unavailable", "SecurityError"); } });
  });
  await page.goto("./?mode=php-detect");
  await expect(page.getByRole("radio", { name: "Dark", exact: true })).toBeChecked();
  await page.locator('label[title="Light"]').click();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect(page.getByRole("status")).toHaveText("Theme applies for this visit.");
  await page.locator('label[title="Dark"]').click();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
});

test("theme changes synchronize across open tabs", async ({ page, context }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const other = await context.newPage();
  await other.goto(page.url());
  await other.locator('label[title="Light"]').click();
  await expect(page.getByRole("radio", { name: "Light", exact: true })).toBeChecked();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await other.close();
});

test("a loaded sample can be rerun offline", async ({ page, context }): Promise<void> => {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await context.setOffline(true);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("unavailable syntax highlighting leaves source editing and analysis usable", async ({ page, context, isMobile }): Promise<void> => {
  const errors: string[] = [];
  const blockedGrammars: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await context.route("**/*.js", async (route): Promise<void> => {
    const response = await route.fetch();
    const source: string = await response.text();
    if (source.includes("Heredoc") && source.includes("PhpOpen")) {
      blockedGrammars.push(route.request().url());
      await route.abort("failed");
    } else {
      await route.fulfill({ response });
    }
  });
  if (isMobile) await page.getByRole("button", { name: "Faithful WAT", exact: true }).click();
  await page.getByRole(isMobile ? "option" : "button", { name: "Detect & Peel", exact: true }).click();
  const inputPanel = page.locator("section").filter({ has: page.getByRole("heading", { name: "Detect & Peel", exact: true }) });
  await expect(inputPanel.getByRole("status")).toContainText("Syntax highlighting could not load. Reconnect and reload the page.");
  await page.locator(".cm-content[contenteditable=true]").fill("<?php echo 42;");
  await expect(page.getByText("Load an artifact or run the current sample to see recovered output here.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Run analysis", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true }).locator(".cm-content")).toContainText("echo 42;");
  expect(blockedGrammars).toHaveLength(1);
  expect(errors).toEqual([]);
});

test("invalid binary input reports an error and the sample restores recovery", async ({ page }): Promise<void> => {
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "empty.wasm", mimeType: "application/wasm", buffer: Buffer.alloc(0) });
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("large invalid binary input keeps the hex view bounded", async ({ page }): Promise<void> => {
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "zeros.wasm", mimeType: "application/wasm", buffer: Buffer.alloc(1024 * 1024) });
  await expect(page.getByRole("alert")).toBeVisible();
  const grid = page.getByRole("grid");
  const bytesPerRow: number = Number(await grid.getAttribute("aria-colcount")) - 1;
  expect(bytesPerRow).toBeGreaterThan(0);
  await expect(grid).toHaveAttribute("aria-rowcount", String(Math.ceil(1024 * 1024 / bytesPerRow)));
  expect(await grid.getByRole("row").count()).toBeLessThan(80);
  await grid.focus();
  await page.keyboard.press("ControlOrMeta+End");
  await expect(grid.getByRole("gridcell", { name: "Offset 0fffff: 00", exact: true })).toHaveAttribute("aria-selected", "true");
});

test("reduced motion and system contrast retain usable controls", async ({ page }, testInfo): Promise<void> => {
  await page.emulateMedia({ reducedMotion: "reduce", forcedColors: "active" });
  await page.goto("./?mode=php-detect");
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
  for (const theme of ["Light", "Dark"]) {
    await page.locator(`label[title="${theme}"]`).click();
    await page.getByRole("button", { name: "Run analysis", exact: true }).click();
    await expect(page.getByRole("radio", { name: theme, exact: true })).toBeChecked();
    expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    await page.screenshot({ path: testInfo.outputPath(`system-contrast-${theme.toLowerCase()}.png`) });
  }
});
