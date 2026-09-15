import { expect, test } from "@playwright/test";

test("clipboard denial explains recovery and permits a retry", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    let attempts: number = 0;
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: (text: string): Promise<void> => {
          if (attempts++ === 0) return Promise.reject(new DOMException("Clipboard permission denied", "NotAllowedError"));
          if (!text.includes("i32.add")) return Promise.reject(new Error("The recovered output was not copied"));
          return Promise.resolve();
        },
      },
    });
  });
  await page.goto("./?mode=wasm-faithful-wat");
  await page.getByRole("button", { name: "Copy code", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("Copy failed. Select the code to copy it manually, or try again.");
  await page.getByRole("button", { name: "Copy code", exact: true }).click();
  await expect(page.getByRole("button", { name: "Copied code", exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});
