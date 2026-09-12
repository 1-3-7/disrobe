import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

test("real Wasm recovery, download, and both neutral themes work", async ({ page }): Promise<void> => {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  page.on("console", (message): void => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("response", (response): void => {
    if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
  });
  await page.goto("./?mode=wasm-faithful-wat");
  await expect(page.getByRole("radio")).toHaveCount(2);
  await expect(page.getByRole("radio", { name: "Dark", exact: true })).toBeChecked();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await page.getByRole("button", { name: "Run analysis", exact: true }).click();
  await expect(page.getByText("5 functions", { exact: true })).toBeVisible();
  const editor = page.locator(".cm-editor");
  await expect(editor).toHaveCount(1);
  await expect(editor).toContainText("i32.add");
  const coloredTokens = async (): Promise<string[]> => editor.locator(".cm-line span").evaluateAll((spans: Element[]): string[] =>
    [...new Set(spans.map((span: Element): string => getComputedStyle(span).color))].filter((color: string): boolean => !/^rgb\((\d+), \1, \1\)$/u.test(color)));
  await expect.poll(coloredTokens).toEqual(expect.arrayContaining(["rgb(255, 123, 114)", "rgb(121, 192, 255)"]));
  const pendingDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await pendingDownload;
  const downloadPath: string | null = await download.path();
  if (downloadPath === null) throw new Error("The WAT download did not produce a file");
  const source: string = await readFile(downloadPath, "utf8");
  expect(source.length).toBeLessThan(65_536);
  expect(source).toContain('(export "add"');
  expect(source).toContain('(export "fib"');
  expect(source).toContain("i32.add");
  await page.locator('label[title="Light"]').click();
  await expect(page.getByRole("radio", { name: "Light", exact: true })).toBeChecked();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect(editor).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect.poll(coloredTokens).toEqual(expect.arrayContaining(["rgb(207, 34, 46)", "rgb(5, 80, 174)"]));
  await page.reload();
  await expect(page.getByRole("radio", { name: "Light", exact: true })).toBeChecked();
  await page.locator('label[title="Dark"]').click();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(17, 17, 17)");
  await expect(editor).toHaveCSS("background-color", "rgb(17, 17, 17)");
  expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  expect(errors).toEqual([]);
});

test("editable source distinguishes keywords, strings and numbers in both themes", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const content = page.locator(".cm-content[contenteditable=true]");
  await content.click();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.insertText('<?php $answer = 42; echo "hello";');
  for (const [theme, expected] of [
    ["Dark", ["rgb(255, 123, 114)", "rgb(165, 214, 255)", "rgb(121, 192, 255)"]],
    ["Light", ["rgb(207, 34, 46)", "rgb(10, 48, 105)", "rgb(5, 80, 174)"]],
  ] as const) {
    await page.locator(`label[title="${theme}"]`).click();
    await expect.poll(() => content.locator("span").evaluateAll((spans: Element[]): string[] =>
      [...new Set(spans.map((span: Element): string => getComputedStyle(span).color))])).toEqual(expect.arrayContaining([...expected]));
  }
});

test("PHP tag literals stay inside fragments while tagged documents retain highlighting", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  const content = page.locator(".cm-content[contenteditable=true]");
  const sources: readonly string[] = [
    'echo "<?php";',
    '/* <?php */\necho "hello";',
    '$text = <<<TXT\n<?php\nTXT;\necho $text;',
    '<?php echo "hello"; ?>',
  ];
  for (const [theme, keyword] of [["Dark", "rgb(255, 123, 114)"], ["Light", "rgb(207, 34, 46)"]] as const) {
    await page.locator(`label[title="${theme}"]`).click();
    for (const source of sources) {
      await content.click();
      await page.keyboard.press("ControlOrMeta+A");
      await page.keyboard.insertText(source);
      await expect(content.locator("span").filter({ hasText: /^echo$/ })).toHaveCSS("color", keyword);
    }
  }
});
