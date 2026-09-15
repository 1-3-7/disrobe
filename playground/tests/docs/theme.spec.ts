import { expect, test, type Page } from "@playwright/test";

function captureErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  page.on("console", (message): void => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("response", (response): void => {
    if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
  });
  return errors;
}

test("two neutral themes switch, survive navigation, and load their assets", async ({ page }): Promise<void> => {
  const errors: string[] = captureErrors(page);
  await page.goto("/capabilities.html");
  const picker = page.getByRole("combobox", { name: "Color theme" });
  await expect(picker.locator("option")).toHaveText(["Dark", "Light"]);
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await expect(page.locator("body")).toHaveCSS("color", "rgb(245, 245, 245)");
  await expect(page.locator("html")).toHaveCSS("color-scheme", "dark");
  await picker.selectOption({ label: "Light" });
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect(page.locator("body")).toHaveCSS("color", "rgb(23, 23, 23)");
  await page.goto("/installation.html");
  await expect(picker.locator("option:checked")).toHaveText("Light");
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await picker.selectOption({ label: "Dark" });
  await page.reload();
  await expect(picker.locator("option:checked")).toHaveText("Dark");
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await page.evaluate(async (): Promise<void> => { await document.fonts.ready; });
  const layout = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth > innerWidth,
    loadedFonts: [...document.fonts].filter((font: FontFace): boolean => font.status === "loaded").map((font: FontFace): string => font.family),
  }));
  expect(layout.overflow).toBe(false);
  expect(layout.loadedFonts).toEqual(expect.arrayContaining(["Manrope", "JetBrains Mono"]));
  expect(layout.loadedFonts).not.toEqual(expect.arrayContaining(["Inter"]));
  expect(errors).toEqual([]);
});

test("theme changes work when saving browser preferences is unavailable", async ({ page }): Promise<void> => {
  const errors: string[] = captureErrors(page);
  await page.addInitScript((): void => {
    Storage.prototype.setItem = (): never => { throw new DOMException("Storage unavailable", "QuotaExceededError"); };
  });
  await page.goto("/capabilities.html");
  const picker = page.getByRole("combobox", { name: "Color theme" });
  await picker.selectOption({ label: "Light" });
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await picker.selectOption({ label: "Dark" });
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await expect(picker).toHaveAttribute("title", "Theme applies for this visit.");
  expect(errors).toEqual([]);
});

test("a saved legacy theme migrates to one of the two choices", async ({ page }): Promise<void> => {
  const errors: string[] = captureErrors(page);
  await page.addInitScript((): void => { localStorage.setItem("mdbook-theme", "navy"); });
  await page.goto("/capabilities.html");
  const picker = page.getByRole("combobox", { name: "Color theme" });
  await expect(picker.locator("option:checked")).toHaveText("Dark");
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await picker.selectOption({ label: "Light" });
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  expect(errors).toEqual([]);
});

test("syntax tokens have distinct colors on both neutral themes", async ({ page }): Promise<void> => {
  await page.goto("/capabilities.html");
  await page.evaluate((): void => {
    const sample: HTMLPreElement = document.createElement("pre");
    sample.id = "syntax-colors";
    sample.className = "hljs";
    for (const name of ["keyword", "string", "number", "title function_", "addition", "deletion"]) {
      const token: HTMLSpanElement = document.createElement("span");
      token.className = `hljs-${name}`;
      token.textContent = name;
      sample.append(token);
    }
    document.body.append(sample);
  });
  for (const [label, expected] of [
    ["Dark", ["rgb(255, 123, 114)", "rgb(165, 214, 255)", "rgb(121, 192, 255)", "rgb(210, 168, 255)", "rgb(165, 214, 255)", "rgb(255, 123, 114)"]],
    ["Light", ["rgb(207, 34, 46)", "rgb(10, 48, 105)", "rgb(5, 80, 174)", "rgb(102, 57, 186)", "rgb(10, 48, 105)", "rgb(207, 34, 46)"]],
  ] as const) {
    await page.getByRole("combobox", { name: "Color theme" }).selectOption({ label });
    const colors: string[] = await page.locator("#syntax-colors span").evaluateAll((tokens: Element[]): string[] =>
      tokens.map((token: Element): string => getComputedStyle(token).color));
    expect(colors, `${label} syntax colors`).toEqual(expected);
  }
});
