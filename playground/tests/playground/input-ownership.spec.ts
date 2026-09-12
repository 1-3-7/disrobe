import { expect, test } from "@playwright/test";

test("uploaded bytes remain unchanged in text analysis modes", async ({ page }): Promise<void> => {
  await page.goto("./?mode=ioc");
  const bytes: Buffer = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("https://example.org/utf16", "utf16le")]);
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "indicators.bin", mimeType: "application/octet-stream", buffer: bytes });
  await expect(page.getByTestId("input-metadata")).toContainText(`${bytes.length} B`);
  await expect(page.getByText("binary input", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("https://example.org/utf16");
});

test("changing modes keeps an uploaded artifact until a sample is requested", async ({ page, isMobile }): Promise<void> => {
  await page.goto("./?mode=strings");
  const bytes: Buffer = Buffer.from("https://example.org/my-artifact\n");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "my-artifact.txt", mimeType: "text/plain", buffer: bytes });
  await expect(page.getByTestId("input-metadata")).toContainText("my-artifact.txt");
  if (isMobile) await page.getByRole("button", { name: "Strings", exact: true }).click();
  await page.getByRole(isMobile ? "option" : "button", { name: "IOCs", exact: true }).click();
  await expect(page.getByTestId("input-metadata")).toContainText("my-artifact.txt");
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("https://example.org/my-artifact");
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByTestId("input-metadata")).not.toContainText("my-artifact.txt");
});

test("a delayed sample cannot replace the newly selected mode's input", async ({ page, isMobile }): Promise<void> => {
  const pending = Promise.withResolvers<void>();
  const requested = Promise.withResolvers<void>();
  await page.route("**/samples/arith4.wasm", async (route): Promise<void> => {
    requested.resolve();
    await pending.promise;
    await route.continue();
  });
  await page.goto("./?mode=wasm-faithful-wat");
  await requested.promise;
  const canceled = page.waitForEvent("requestfailed", {
    predicate: (request): boolean => request.url().endsWith("/samples/arith4.wasm"),
  });
  if (isMobile) {
    await page.getByRole("button", { name: "Faithful WAT", exact: true }).click();
    await page.getByRole("option", { name: "Detect & Peel", exact: true }).click();
  } else {
    await page.getByRole("button", { name: "Detect & Peel", exact: true }).click();
  }
  await expect(page.getByRole("heading", { name: "Detect & Peel", exact: true })).toBeVisible();
  await expect(page.locator(".cm-content[contenteditable=true]")).toContainText("<?php");
  pending.resolve();
  expect((await canceled).failure()?.errorText).toContain("ERR_ABORTED");
  await page.evaluate((): Promise<void> => new Promise((resolve): void => {
    requestAnimationFrame((): void => { resolve(); });
  }));
  await page.getByRole("button", { name: "Run analysis", exact: true }).click();
  await expect(page.locator(".cm-content[contenteditable=true]")).toContainText("<?php");
  await expect(page.getByText("arith4.wasm", { exact: true })).toHaveCount(0);
});

test("editing the input clears the previous result", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const outputHeader = page.getByRole("heading", { name: "output", exact: true }).locator("../..");
  const completed = outputHeader.getByText("php_detect", { exact: true });
  await expect(completed).toBeVisible();
  const input = page.locator(".cm-content[contenteditable=true]");
  await input.fill("<?php echo 42;");
  await expect(completed).toHaveCount(0);
  await expect(page.getByText("Load an artifact or run the current sample to see recovered output here.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Run analysis", exact: true }).click();
  await expect(completed).toBeVisible();
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(input).toContainText("base64_decode");
  await expect(completed).toBeVisible();
});
