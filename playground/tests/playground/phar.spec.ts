import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

test("PHAR members download unchanged and can become the next input", async ({ page }): Promise<void> => {
  const source: Buffer = await readFile(new URL("../../../corpus/php/phar-bz2/src/lib/math.php", import.meta.url));
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/php/phar/bzip2.phar", import.meta.url)));
  await page.getByRole("button", { name: "Run in Extract PHAR", exact: true }).click({ timeout: 10_000 });
  await page.getByRole("combobox", { name: "Archive member", exact: true }).selectOption({ label: "lib/math.php" });
  await page.getByRole("button", { name: "Extract member", exact: true }).click();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download member", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("math.php");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The PHAR download has no file");
  expect(await readFile(path)).toEqual(source);
  await page.getByRole("button", { name: "Use as input", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Auto Route", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run in Detect & Peel", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("math.php");
  await expect(page.getByTestId("input-metadata")).toContainText(`${source.length} B`);
  await expect(page.getByRole("button", { name: "Run in Extract PHAR", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Download member", exact: true })).toHaveCount(0);
});
