import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

test("JVM class recovery exposes source and constructor bytecode", async ({ page }): Promise<void> => {
  await page.goto("./?mode=jvm-class");
  await expect(page.getByRole("heading", { name: "implementors.Direct", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("Root");
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Java", exact: true }).click();
  const download = await event;
  expect(download.suggestedFilename()).toBe("Direct.java");
  const path: string | null = await download.path();
  if (path === null) throw new Error("Java source download has no path");
  const source: string = await readFile(path, "utf8");
  expect(source).toContain("class Direct");
  expect(source).toContain("Root");
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("invokespecial");
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("java/lang/Object");
  for (const theme of ["Dark", "Light"]) {
    await page.locator(`label[title="${theme}"]`).click();
    await expect(page.getByRole("region", { name: "output", exact: true }).locator(".cm-content span").first()).toBeVisible();
    const colors: string[] = await page.getByRole("region", { name: "output", exact: true }).locator(".cm-content").evaluate((node): string[] => [...new Set(Array.from(node.querySelectorAll("span"), (span): string => getComputedStyle(span).color))]);
    expect(colors.length).toBeGreaterThanOrEqual(3);
    await page.getByRole("button", { name: "Java", exact: true }).click();
    await expect(page.getByRole("region", { name: "output", exact: true }).locator(".cm-content span").first()).toBeVisible();
    const sourceColors: string[] = await page.getByRole("region", { name: "output", exact: true }).locator(".cm-content").evaluate((node): string[] => [...new Set(Array.from(node.querySelectorAll("span"), (span): string => getComputedStyle(span).color))]);
    expect(sourceColors.length).toBeGreaterThanOrEqual(3);
    await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  }
  await page.getByRole("button", { name: "Metadata", exact: true }).click();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("implementors.Root");
});

test("JVM input errors retain a working class recovery path", async ({ page }): Promise<void> => {
  await page.goto("./?mode=jvm-class");
  await expect(page.getByRole("heading", { name: "implementors.Direct", exact: true })).toBeVisible();
  for (const bytes of [Buffer.from([0xca, 0xfe, 0xba, 0xbe]), Buffer.alloc(8 * 1024 * 1024 + 1)]) {
    await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "broken.class", mimeType: "application/octet-stream", buffer: bytes });
    await expect(page.getByRole("alert")).toBeVisible();
    if (bytes.length > 8 * 1024 * 1024) await expect(page.getByRole("alert")).toContainText("8 MiB");
  }
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../crates/disrobe-pass-jvm/tests/fixtures/implementors/classes/Direct.class", import.meta.url)));
  await expect(page.getByRole("heading", { name: "implementors.Direct", exact: true })).toBeVisible();
});

test("automatic routing preserves the uploaded Java class", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../crates/disrobe-pass-jvm/tests/fixtures/implementors/classes/Direct.class", import.meta.url)));
  await page.getByRole("button", { name: "Run in Recover Java Class", exact: true }).click();
  await expect(page.getByRole("heading", { name: "implementors.Direct", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("Direct.class");
});

test("Kotlin class recovery exposes the original method and exception regions", async ({ page }): Promise<void> => {
  await page.goto("./?mode=jvm-class");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../crates/disrobe-pass-jvm/tests/fixtures/kotlin_finally_nested/FinallyNested.class", import.meta.url)));
  await expect(page.getByRole("heading", { name: "probe.FinallyNested", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Metadata", exact: true }).click();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download JSON", exact: true }).click();
  const artifact = await event;
  expect(artifact.suggestedFilename()).toBe("FinallyNested.json");
  const path: string | null = await artifact.path();
  if (path === null) throw new Error("JVM report has no download path");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({ name: "probe/FinallyNested", major_version: 61, methods: expect.arrayContaining([expect.objectContaining({ name: "compute", descriptor: "(II)I", code: expect.objectContaining({ state: "available", exceptions: expect.arrayContaining([expect.objectContaining({ catch_type: expect.any(Number) })]) }) })]) });
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  await expect(page.getByLabel("Method", { exact: true })).toBeEnabled();
  await page.getByLabel("Method", { exact: true }).selectOption({ label: "compute(II)I" });
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("idiv");
});

test("JVM abstract and native methods have no bytecode and constants remain exact", async ({ page }): Promise<void> => {
  await page.goto("./?mode=jvm-class");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../crates/disrobe-pass-jvm/tests/fixtures/browser_shapes/BrowserShapes.class", import.meta.url)));
  await expect(page.getByRole("heading", { name: "BrowserShapes", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("9007199254740993L");
  await page.getByText("Recovery details", { exact: true }).click();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("Lifted bodies3");
  await page.getByRole("button", { name: "Bytecode", exact: true }).click();
  for (const label of ["absent(I)I", "nativeCall()I"]) {
    await page.getByLabel("Method", { exact: true }).selectOption({ label });
    await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("This method has no Code attribute");
    await expect(page.getByRole("button", { name: "Download bytecode", exact: true })).toHaveCount(0);
  }
  await page.getByLabel("Method", { exact: true }).selectOption({ label: "grade(I)Ljava/lang/String;" });
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("lookupswitch");
  await page.getByRole("button", { name: "Metadata", exact: true }).click();
  await expect(page.getByRole("region", { name: "output", exact: true }).locator("dd").last()).toHaveText("43");
});
