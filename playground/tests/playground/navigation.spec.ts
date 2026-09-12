import { expect, test } from "@playwright/test";
import { ALL_MODES } from "../../src/lib/modes";

test("browser back and forward restore modes without discarding the user's input", async ({ page, isMobile }): Promise<void> => {
  await page.goto("./?mode=strings");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "navigation.txt", mimeType: "text/plain", buffer: Buffer.from("https://example.org/navigation\n") });
  await expect(page.getByTestId("input-metadata")).toContainText("navigation.txt");
  if (isMobile) await page.getByRole("button", { name: "Strings", exact: true }).click();
  await page.getByRole(isMobile ? "option" : "button", { name: "IOCs", exact: true }).click();
  await expect(page).toHaveURL(/mode=ioc/u);
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Strings", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("navigation.txt");
  await page.goForward();
  await expect(page.getByRole("heading", { name: "IOCs", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "output", exact: true })).toContainText("https://example.org/navigation");
});

test("mode search accepts multiple words and selects with the keyboard", async ({ page, isMobile }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const search = isMobile
    ? page.getByRole("combobox", { name: "Find an analysis mode", exact: true })
    : page.getByRole("searchbox", { name: "Filter analysis modes", exact: true });
  await search.fill("  WASM faithful  ");
  if (isMobile) {
    await expect(page.getByRole("option")).toHaveCount(1);
    await search.press("ArrowDown");
    await search.press("Enter");
  } else {
    await expect(page.getByRole("navigation", { name: "analysis modes" }).getByRole("button")).toHaveCount(1);
    await search.press("Tab");
    await page.keyboard.press("Enter");
  }
  await expect(page.getByRole("heading", { name: "Faithful WAT", exact: true })).toBeVisible();
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  await expect(page).toHaveURL(/mode=wasm-faithful-wat/u);
});

test("an empty search result can be cleared without changing the mode", async ({ page, isMobile }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const search = isMobile
    ? page.getByRole("combobox", { name: "Find an analysis mode", exact: true })
    : page.getByRole("searchbox", { name: "Filter analysis modes", exact: true });
  await search.fill("no-such-analysis-mode");
  await expect(page.getByRole("status").filter({ hasText: "No modes match" })).toBeVisible();
  await search.press("Escape");
  await expect(page.getByRole("heading", { name: "Detect & Peel", exact: true })).toBeVisible();
  if (isMobile) {
    await expect(search).toHaveValue("Detect & Peel");
    await expect(page.getByRole("listbox")).toHaveCount(0);
  } else {
    await expect(search).toHaveValue("");
    await expect(page.getByRole("navigation", { name: "analysis modes" }).getByRole("button")).toHaveCount(ALL_MODES.length);
  }
});
