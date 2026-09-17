import { expect, test } from "@playwright/test";

test("hex bytes support keyboard navigation, range selection, and search", async ({ page }): Promise<void> => {
  await page.goto("./?mode=wasm-faithful-wat");
  const grid = page.getByRole("grid", { name: "hex bytes for arith4.wasm", exact: true });
  await grid.focus();
  await expect(grid.getByRole("gridcell", { name: "Offset 000000: 00", exact: true })).toHaveAttribute("aria-selected", "true");
  await grid.press("ArrowRight");
  await expect(grid.getByRole("gridcell", { name: "Offset 000001: 61 (a)", exact: true })).toHaveAttribute("aria-selected", "true");
  await grid.press("Shift+ArrowRight");
  await expect(page.getByText("selection 2", { exact: true })).toBeVisible();
  await grid.getByRole("gridcell", { name: "Offset 000003: 6d (m)", exact: true }).click();
  await expect(page.getByText("offset 0x000003", { exact: true })).toBeVisible();
  await grid.press("Control+End");
  await expect(page.getByText("offset 0x00012f", { exact: true })).toBeVisible();
  await expect(grid.getByRole("gridcell").last()).toHaveAttribute("aria-selected", "true");
  const search = page.getByRole("textbox", { name: "Search hex or ascii", exact: true });
  await search.fill("00 61 73 6d");
  await search.press("Enter");
  await expect(page.getByText("match @ 0x000000", { exact: true })).toBeVisible();
  await expect(page.getByText("selection 4", { exact: true })).toBeVisible();
});
