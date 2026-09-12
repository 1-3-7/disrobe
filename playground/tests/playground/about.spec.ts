import AxeBuilder from "@axe-core/playwright";
import { expect, test, type TestInfo } from "@playwright/test";

test("about commands are readable and copyable in both themes", async ({ page, context }, testInfo: TestInfo): Promise<void> => {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  page.on("console", (message): void => {
    if (message.type() === "error" || message.type() === "warning") errors.push(message.text());
  });
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("./?mode=about");
  const article = page.getByRole("article");
  await expect(article.getByRole("heading", { level: 1 })).toHaveCSS("font-family", /Manrope/u);
  await expect(article.locator(".cm-editor")).toHaveCount(2);
  await expect(article).not.toContainText("JVM and Dalvik decompilation, and .NET assembly recovery.");
  const commands = article.locator(".cm-editor").last();
  for (const [theme, optionColor] of [
    ["Dark", "rgb(255, 166, 87)"],
    ["Light", "rgb(149, 56, 0)"],
  ] as const) {
    await page.locator(`label[title="${theme}"]`).click();
    await expect(commands.locator("span").filter({ hasText: /^--help$/u })).toHaveCSS("color", optionColor);
    expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    const accessibility = await new AxeBuilder({ page }).include("article").analyze();
    expect(accessibility.violations).toEqual([]);
    await commands.screenshot({ path: testInfo.outputPath(`commands-${theme.toLowerCase()}.png`) });
  }
  await article.getByRole("button", { name: "Copy code", exact: true }).last().click();
  await expect(article.getByRole("button", { name: "Copied code", exact: true })).toBeVisible();
  const copied: string = await page.evaluate((): Promise<string> => navigator.clipboard.readText());
  expect(copied.split(/\r?\n/u)).toEqual([
    "disrobe identify path/to/artifact",
    "disrobe auto path/to/artifact --out recovered/ --capture-stages",
    "disrobe catalog",
    "disrobe --help",
  ]);
  expect(errors).toEqual([]);
});
