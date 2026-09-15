import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { writeFile } from "node:fs/promises";
import { ALL_MODES } from "../../src/lib/modes";

for (const mode of ALL_MODES) {
  if (mode.entry === null || mode.sample === undefined) continue;

  test(`${mode.id} renders its bundled sample`, async ({ page, isMobile }, testInfo): Promise<void> => {
    const errors: string[] = [];
    page.on("pageerror", (error: Error): void => { errors.push(error.message); });
    page.on("console", (message): void => {
      if (message.type() === "error" || message.type() === "warning") errors.push(message.text());
    });
    page.on("response", (response): void => {
      if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
    });
    await page.goto(`./?mode=${mode.id}`);
    const outputHeader = page.getByRole("heading", { name: "output", exact: true }).locator("../..");
    await expect(outputHeader.getByText(mode.entry ?? "", { exact: true })).toBeVisible({ timeout: 12_000 });
    await expect(page.getByRole("alert")).toHaveCount(0);
    await page.getByRole("button", { name: "Run analysis", exact: true }).click();
    await expect(outputHeader.getByText(mode.entry ?? "", { exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    expect(errors).toEqual([]);
    if (!isMobile) await page.screenshot({ path: testInfo.outputPath(`${mode.id}.png`) });
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      const accessibility = await new AxeBuilder({ page }).analyze();
      const reportPath: string = testInfo.outputPath(`accessibility-${theme.toLowerCase()}.json`);
      await writeFile(reportPath, JSON.stringify({
          theme,
          engine: accessibility.testEngine,
          url: accessibility.url,
          timestamp: accessibility.timestamp,
          violations: accessibility.violations,
          incomplete: accessibility.incomplete,
          passes: accessibility.passes.map((rule): string => rule.id),
        }));
      await testInfo.attach(`accessibility-${theme.toLowerCase()}`, {
        path: reportPath,
        contentType: "application/json",
      });
      const failures = accessibility.violations
        .filter((violation): boolean => violation.impact === "critical" || violation.impact === "serious")
        .map((violation) => ({ id: violation.id, impact: violation.impact, count: violation.nodes.length, examples: violation.nodes.slice(0, 3).map((node) => ({ target: node.target, checks: node.any.map((check) => check.data) })) }));
      expect(failures).toEqual([]);
    }
  });
}
