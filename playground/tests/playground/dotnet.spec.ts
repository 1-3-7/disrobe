import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

test("managed assembly recovery exposes its types and CIL", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dotnet");
  await expect(page.getByRole("heading", { name: "Recover .NET Assembly", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("Sample.Shapes");
  await expect(page.getByRole("button", { name: "Download C#", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "CIL", exact: true }).click();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("ret");
});

test("all three .NET source languages have colored complete downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dotnet");
  for (const [label, extension, declaration] of [["C#", "cs", "public string Grade"], ["F#", "fs", "member Grade"], ["Visual Basic", "vb", "Function Grade"]] as const) {
    await page.getByRole("button", { name: label, exact: true }).click();
    const event = page.waitForEvent("download");
    await page.getByRole("button", { name: `Download ${label}`, exact: true }).click();
    const artifact = await event;
    expect(artifact.suggestedFilename()).toMatch(new RegExp(`\\.${extension}$`));
    const path: string | null = await artifact.path();
    if (path === null) throw new Error("Recovered method has no download path");
    const source: string = await readFile(path, "utf8");
    expect(source).toContain(declaration);
    for (const token of ["90", "80", "70", '"A"', '"B"', '"C"', '"F"']) expect(source).toContain(token);
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      const editor = page.getByRole("region", { name: "output", exact: true }).locator(".cm-content");
      await expect(editor.locator("span").first()).toBeVisible();
      const colors: string[] = await editor.evaluate((node): string[] => [...new Set(Array.from(node.querySelectorAll("span"), (span): string => getComputedStyle(span).color))]);
      expect(colors.length).toBeGreaterThanOrEqual(3);
    }
  }
});

test("bodyless methods and exception regions remain distinct", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dotnet");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/dotnet/megafile/EdgeCases.baseline.dll", import.meta.url)));
  const methods = page.getByLabel("Method", { exact: true });
  const absent: string | null = await methods.locator("option").filter({ hasText: "AnimalBase.Sound" }).getAttribute("value");
  if (absent === null) throw new Error("Missing original abstract Sound method");
  await methods.selectOption(absent);
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("This method has no stored body");
  await page.getByRole("button", { name: "CIL", exact: true }).click();
  await expect(page.getByRole("button", { name: "Download CIL", exact: true })).toHaveCount(0);
  const handler: string | null = await methods.locator("option").filter({ hasText: "ExceptionPlayground.SafeDivide" }).getAttribute("value");
  if (handler === null) throw new Error("Missing original SafeDivide method");
  await methods.selectOption(handler);
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("div");
  await page.getByRole("button", { name: "Metadata", exact: true }).click();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download JSON", exact: true }).click();
  const artifact = await event;
  const path: string | null = await artifact.path();
  if (path === null) throw new Error("Metadata report has no download path");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({ bytecode: expect.arrayContaining([expect.objectContaining({ token: Number(handler), code: expect.objectContaining({ state: "available", exceptions: expect.arrayContaining([expect.objectContaining({ kind: "Finally" })]) }) })]) });
});

test("managed input bounds reject invalid files and preserve followup", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dotnet");
  for (const buffer of [Buffer.from("MZ"), Buffer.alloc(8 * 1024 * 1024 + 1)]) {
    await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "broken.dll", mimeType: "application/octet-stream", buffer });
    await expect(page.getByRole("alert")).toBeVisible();
    if (buffer.length > 8 * 1024 * 1024) await expect(page.getByRole("alert")).toContainText("8 MiB");
  }
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/dotnet/shapes/Shapes.dll", import.meta.url)));
  await expect(page.getByRole("button", { name: "Download C#", exact: true })).toBeVisible();
});

test("automatic routing preserves an uploaded managed assembly", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../../corpus/dotnet/shapes/Shapes.dll", import.meta.url)));
  await page.getByRole("button", { name: "Run in Recover .NET Assembly", exact: true }).click();
  await expect(page.getByRole("button", { name: "Download C#", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("Shapes.dll");
});
