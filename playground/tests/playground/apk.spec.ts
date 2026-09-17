import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

test("a resource-only APK routes to decoded Android XML", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/apk/fixture-res.apk", import.meta.url)));
  await page.getByRole("button", { name: "Run in Inspect APK", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Inspect APK", exact: true })).toBeVisible();
  await expect(page.locator(".cm-editor")).toContainText("<manifest");
  await page.getByRole("button", { name: "Resources", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Resource file", exact: true })).toBeVisible();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/\.xml$/u);
  const path: string | null = await download.path();
  if (path === null) throw new Error("The Android XML download has no file");
  expect(await readFile(path, "utf8")).toContain("http://schemas.android.com/apk/res/android");
});

test("APK signing metadata is distinct from signature verification", async ({ page }): Promise<void> => {
  await page.goto("./?mode=apk");
  await expect(page.getByText("com.disrobe.fixture", { exact: true })).toBeVisible();
  await expect(page.getByText("Signatures are parsed, not verified.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText('"format": "apk"');
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "invalid.apk", mimeType: "application/octet-stream", buffer: Buffer.from("ordinary text") });
  await expect(page.getByRole("alert")).toContainText("APK archive");
  await expect(page.getByText("com.disrobe.fixture", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByText("com.disrobe.fixture", { exact: true })).toBeVisible();
});
