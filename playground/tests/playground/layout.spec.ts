import { expect, test } from "@playwright/test";

test("keyboard users can bypass navigation and run edited source", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to analysis", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();
  for (let step: number = 0; step < 12; step += 1) {
    await page.keyboard.press("Tab");
    if (await page.locator(".cm-content[contenteditable=true]").evaluate((element): boolean => element === document.activeElement)) break;
  }
  await expect(page.locator(".cm-content[contenteditable=true]")).toBeFocused();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.insertText('<?php echo "Résumé Δ";');
  await page.keyboard.press("ControlOrMeta+Enter");
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
  await expect(page.getByLabel("recovered source", { exact: true })).toContainText('<?php echo "Résumé Δ";');
});

test("editing and running in the same event submits the current document", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const input = page.locator(".cm-content[contenteditable=true]");
  await input.click();
  await page.keyboard.press("ControlOrMeta+A");
  const source: string = '<?php echo "current document Δ";';
  await input.evaluate((element: Element, text: string): void => {
    if (!document.execCommand("insertText", false, text)) throw new Error("Browser edit was rejected");
    const options: KeyboardEventInit = { key: "Enter", code: "Enter", keyCode: 13, ctrlKey: true, bubbles: true, cancelable: true };
    element.dispatchEvent(new KeyboardEvent("keydown", options));
    element.dispatchEvent(new KeyboardEvent("keyup", options));
  }, source);
  await expect(page.getByLabel("recovered source", { exact: true })).toContainText(source);
});

test("same-page navigation preserves an edited input without starting analysis", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  await expect(page.getByLabel("recovered source", { exact: true })).toBeVisible();
  const input = page.locator(".cm-content[contenteditable=true]");
  const source: string = '<?php echo "navigation preserves input";';
  await input.fill(source);
  const idle = page.getByTestId("input-metadata").getByText("idle", { exact: true });
  await expect(idle).toBeVisible();
  await page.evaluate((): Promise<void> => new Promise<void>((resolve): void => {
    window.addEventListener("popstate", (): void => { resolve(); }, { once: true });
    window.location.hash = "analysis";
  }));
  await expect(idle).toBeVisible();
  await expect(input).toHaveText(source);
});

for (const width of [375, 768, 1024, 1280, 1440, 1920]) {
  test(`analysis panels remain usable at ${width}px`, async ({ page }, testInfo): Promise<void> => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("./?mode=wasm-faithful-wat");
    await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      if (width >= 1024) {
        await page.getByRole("button", { name: "Collapse sidebar", exact: true }).click();
        await expect(page.getByRole("button", { name: "Expand sidebar", exact: true })).toBeVisible();
        await page.getByRole("button", { name: "Expand sidebar", exact: true }).click();
      }
      await page.getByRole("button", { name: "Run analysis", exact: true }).click();
      await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
      if (width === 375) {
        const metadata = page.getByTestId("input-metadata");
        const strip = await metadata.boundingBox();
        expect(strip).not.toBeNull();
        for (const text of ["sample", "size", "state", "arith4.wasm", "304 B", "ready"]) {
          const bounds = await metadata.getByText(text, { exact: true }).boundingBox();
          expect(bounds).not.toBeNull();
          expect(bounds?.y).toBeGreaterThanOrEqual(strip?.y ?? 0);
          expect((bounds?.y ?? 0) + (bounds?.height ?? 0)).toBeLessThanOrEqual((strip?.y ?? 0) + (strip?.height ?? 0));
        }
      }
      expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
      const editor = page.locator(".cm-editor");
      await editor.scrollIntoViewIfNeeded();
      const bounds = await editor.boundingBox();
      expect(bounds?.width).toBeGreaterThan(250);
      expect(bounds?.height).toBeGreaterThan(90);
      await page.screenshot({ path: testInfo.outputPath(`${width}-${theme.toLowerCase()}.png`) });
    }
  });
}
