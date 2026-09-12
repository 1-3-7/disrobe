import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

function unsignedLeb(value: number): number[] {
  const bytes: number[] = [];
  do {
    const byte: number = value & 0x7f;
    value >>>= 7;
    bytes.push(byte | (value === 0 ? 0 : 0x80));
  } while (value !== 0);
  return bytes;
}

function exportedFunction(count: number): Buffer {
  const exports: number[] = unsignedLeb(count);
  for (let index: number = 0; index < count; index += 1) {
    const name: Buffer = Buffer.from(`call_${index}`);
    exports.push(...unsignedLeb(name.length), ...name, 0, 0);
  }
  return Buffer.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    1, 4, 1, 96, 0, 0,
    3, 2, 1, 0,
    7, ...unsignedLeb(exports.length), ...exports,
    10, 4, 1, 2, 0, 11,
  ]);
}

test("WASM link truncation is visible in both themes and clears for complete input", async ({ page }, testInfo): Promise<void> => {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  page.on("console", (message): void => {
    if (message.type() === "error" || message.type() === "warning") errors.push(message.text());
  });
  const buffer: Buffer = exportedFunction(2049);
  expect(WebAssembly.validate(Uint8Array.from(buffer))).toBe(true);
  await page.goto("./?mode=wasm-signatures");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "many-exports.wasm", mimeType: "application/wasm", buffer });
  const notice = page.getByRole("status").filter({ hasText: "Cross-language links:" });
  await expect(notice).toHaveText("Cross-language links: 2,048 of 2,049 retained.");
  await expect(page.getByRole("region", { name: "output", exact: true }).getByText("exports", { exact: true }).locator("..")).toContainText("2049");
  for (const theme of ["Dark", "Light"] as const) {
    await page.locator(`label[title="${theme}"]`).click();
    await expect(notice).toBeVisible();
    const accessibility = await new AxeBuilder({ page }).include('[role="status"]').withRules(["color-contrast"]).analyze();
    expect(accessibility.violations).toEqual([]);
    expect(accessibility.incomplete).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath(`wasm-link-truncation-${theme.toLowerCase()}.png`) });
  }
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "complete.wasm", mimeType: "application/wasm", buffer: exportedFunction(1) });
  await expect(notice).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Download output", exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect(errors).toEqual([]);
});
