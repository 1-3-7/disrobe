import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

test("YARV recovery exposes source and decoded instructions", async ({ page }): Promise<void> => {
  await page.goto("./?mode=ruby-detect");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/ruby/mri/yarv/greeter.rb.yarvc", import.meta.url)));
  await expect(page.getByText("Structural recovery", { exact: true })).toBeVisible();
  await expect(page.locator(".cm-editor")).toContainText("class Greeter");
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("ruby-recovered.rb");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The Ruby source download has no file");
  expect(await readFile(path, "utf8")).toContain("def initialize(who)");
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText("defineclass");
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText('"format": "ruby"');
});

test("mruby recovery keeps operation and byte counts distinct", async ({ page }): Promise<void> => {
  await page.goto("./?mode=ruby-detect");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/ruby/mruby/greet.mrb", import.meta.url)));
  await expect(page.locator(".cm-editor")).toContainText("def greet(arg0)");
  await expect(page.getByText("Instruction bytes", { exact: true }).locator("..")).toContainText("41");
  await expect(page.getByText("Modeled ops", { exact: true }).locator("..")).toContainText("15 / 15");
  await expect(page.getByRole("button", { name: "Bytecode", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText('"format": "ruby"');
});
