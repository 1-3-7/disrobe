import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

test("a Hermes upload routes to recovery and downloads a selected function", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../public/samples/hermes-shapes.hbc", import.meta.url)));
  await page.getByRole("button", { name: "Run in Recover Hermes", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Recover Hermes", exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "Function", exact: true }).selectOption({ label: "1: bigText" });
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("hermes-function-1.js");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The JavaScript download has no file");
  const source: string = await readFile(path, "utf8");
  expect(source).toContain("123456789012345678901234567890");
  expect(source).not.toContain("function makeBox");
});

test("Hermes metadata retains global string IDs and true identifier kinds", async ({ page }): Promise<void> => {
  await page.goto("./?mode=hermes");
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Function", exact: true })).toBeDisabled();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("hermes-report.json");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The Hermes report download has no file");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({
    ok: true,
    header: { version: 96, function_count: 15, string_count: 38, identifier_count: 27 },
    string_table: expect.arrayContaining([{ index: 1, kind: "string", value: "hi-" }, { index: 31, kind: "identifier", value: "makeBox" }]),
  });
});

test("Hermes bytecode remains accessible beside recovered source", async ({ page }): Promise<void> => {
  await page.goto("./?mode=hermes");
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText("DeclareGlobalVar");
  await page.getByRole("combobox", { name: "Function", exact: true }).selectOption({ label: "1: bigText" });
  await expect(page.locator(".cm-editor")).toContainText("LoadConstBigInt");
  await page.getByRole("button", { name: "JavaScript", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText("123456789012345678901234567890");
});

test("invalid Hermes input reports a parse error and the sample still recovers", async ({ page }): Promise<void> => {
  await page.goto("./?mode=hermes");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "invalid.hbc", mimeType: "application/octet-stream", buffer: Buffer.from("ordinary text") });
  await expect(page.getByRole("alert")).toContainText("Hermes bytecode");
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByRole("combobox", { name: "Function", exact: true }).getByRole("option")).toHaveCount(16);
});

test("an unsupported Hermes version keeps its metadata available", async ({ page }): Promise<void> => {
  const bytes: Buffer = await readFile(new URL("../../public/samples/hermes-shapes.hbc", import.meta.url));
  bytes.writeUInt32LE(95, 8);
  await page.goto("./?mode=hermes");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "unsupported-version.hbc", mimeType: "application/octet-stream", buffer: bytes });
  await expect(page.getByRole("status").filter({ hasText: "JavaScript recovery is unavailable for this bytecode version" })).toBeVisible();
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText('"version": 95');
  await expect(page.getByRole("button", { name: "Download output", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText("no opcode table");
});
