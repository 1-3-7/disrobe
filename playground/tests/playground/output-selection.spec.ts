import { expect, test } from "@playwright/test";

test("output selectors keep a visible selection after focus moves", async ({ page }): Promise<void> => {
  for (const mode of ["go", "apk", "dart-kernel", "hermes", "ruby-detect"]) {
    await page.goto(`./?mode=${mode}`);
    const report = page.getByRole("button", { name: "JSON report", exact: true });
    const group = report.locator("..");
    await expect(group.locator("button[aria-pressed=true]")).toHaveCount(1);
    const initial = group.locator("button[aria-pressed=true]");
    const initialName: string | null = await initial.textContent();
    if (initialName === null) throw new Error("Selected output has no name");
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      await report.click();
      await page.getByRole("button", { name: "Run analysis", exact: true }).focus();
      await page.mouse.move(0, 0);
      await expect(report).toHaveAttribute("aria-pressed", "true");
      const other = group.getByRole("button", { name: initialName, exact: true });
      await expect(other).toHaveAttribute("aria-pressed", "false");
      await expect.poll(async (): Promise<boolean> => {
        const selected: string[] = await report.evaluate((node): string[] => [getComputedStyle(node).backgroundColor, getComputedStyle(node).borderColor]);
        const unselected: string[] = await other.evaluate((node): string[] => [getComputedStyle(node).backgroundColor, getComputedStyle(node).borderColor]);
        return selected.some((value, index): boolean => value !== unselected[index]);
      }).toBe(true);
      await other.click();
      await page.getByRole("button", { name: "Run analysis", exact: true }).focus();
      await page.mouse.move(0, 0);
      await expect(other).toHaveAttribute("aria-pressed", "true");
      await expect(report).toHaveAttribute("aria-pressed", "false");
    }
  }
});
