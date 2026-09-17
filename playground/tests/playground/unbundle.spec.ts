import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";

const bundle: URL = new URL("../../../corpus/js/webpack5/gauntlet/bundle.js", import.meta.url);

async function upload(page: Page, source: string | Buffer): Promise<void> {
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "bundle.js", mimeType: "text/javascript", buffer: typeof source === "string" ? Buffer.from(source) : source });
}

async function download(page: Page, name: string): Promise<{ filename: string; bytes: Buffer }> {
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name, exact: true }).click();
  const artifact = await event;
  const path: string | null = await artifact.path();
  if (path === null) throw new Error("Bundle download has no local file");
  return { filename: artifact.suggestedFilename(), bytes: await readFile(path) };
}

test("real webpack modules have highlighted source and exact JSON downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-unbundle");
  await expect(page.getByText("Webpack 5 · 3 modules extracted", { exact: true })).toBeVisible();
  for (const theme of ["Dark", "Light"]) {
    await page.locator(`label[title="${theme}"]`).click();
    const colors: string[] = await page.getByRole("region", { name: "output", exact: true }).locator(".cm-content").evaluate((node): string[] => [...new Set(Array.from(node.querySelectorAll("span"), (span): string => getComputedStyle(span).color))]);
    expect(colors.length).toBeGreaterThanOrEqual(3);
  }
  const modules: Map<string, string> = new Map();
  for (const [name, tokens] of [
    ["geometry.js", ["PI_APPROX", "circleArea", "polygonPerimeter", "too many sides for polygon"]],
    ["inventory.js", ["STORE_NAME", "Warehouse", "restock", "disrobe-webpack-gauntlet"]],
  ] as const) {
    const select = page.getByRole("combobox", { name: "Module", exact: true });
    await select.selectOption({ label: `./src/${name} · main` });
    const artifact = await download(page, "Download module");
    const source: string = artifact.bytes.toString("utf8");
    expect(artifact.filename).toBe(name);
    const original: string = await readFile(new URL(`../../../corpus/js/webpack5/gauntlet/src/${name}`, import.meta.url), "utf8");
    for (const token of tokens) { expect(original).toContain(token); expect(source).toContain(token); }
    expect(source).not.toContain("__webpack_module_cache__");
    modules.set(`./src/${name}`, source);
  }
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  const artifact = await download(page, "Download JSON");
  expect(artifact.filename).toBe("bundle-report.json");
  const report: { state: string; modules: { id: string; source: string }[] } = JSON.parse(artifact.bytes.toString("utf8"));
  expect(report.state).toBe("recognized");
  for (const [id, source] of modules) expect(report.modules.find((module): boolean => module.id === id)?.source).toBe(source);
});

test("bundle detection without modules and unrecognized input remain distinct", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-unbundle");
  await upload(page, "var __webpack_modules__ = {}; var __webpack_module_cache__ = {};");
  await expect(page.getByText("Webpack 5 detected", { exact: true })).toBeVisible();
  await expect(page.getByText("Bundle markers were found, but no module bodies could be extracted. A source map may contain the original files.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Source", exact: true })).toBeDisabled();
  await upload(page, "const value = 42;");
  await expect(page.getByText("No supported bundle found", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("bundle filters preserve distinct chunks and full source downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-unbundle");
  const first: string = `module.exports = '${"x".repeat(70_000)}';`;
  const second: string = "module.exports = 'second chunk';";
  await upload(page, `__webpack_require__.r = function() {}; self.webpackChunkapp.push([[1], {same: function(module, exports) {${first}}}]);\nself.webpackChunkapp.push([[2], {same: function(module, exports) {${second}}}]);`);
  await expect(page.getByText("Webpack 5 · 2 modules extracted", { exact: true })).toBeVisible();
  const select = page.getByRole("combobox", { name: "Module", exact: true });
  await select.selectOption("0");
  await expect(page.getByText("Preview shortened. Downloads contain the complete output.", { exact: true })).toBeVisible();
  expect((await download(page, "Download module")).bytes).toEqual(Buffer.from(first));
  await select.selectOption("1");
  expect((await download(page, "Download module")).bytes).toEqual(Buffer.from(second));
  await page.getByText("Find modules", { exact: true }).click();
  await page.getByRole("searchbox", { name: "Filter modules", exact: true }).fill("missing");
  await expect(page.getByText("No modules match this search.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download module", exact: true })).toBeDisabled();
  await page.getByRole("searchbox", { name: "Filter modules", exact: true }).fill("SAME");
  expect((await download(page, "Download module")).bytes).toEqual(Buffer.from(second));
});

test("bundle input failures preserve the next analysis", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const read: typeof File.prototype.arrayBuffer = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function(this: File): Promise<ArrayBuffer> {
      document.documentElement.setAttribute("data-read-size", String(this.size));
      return read.call(this);
    };
  });
  await page.goto("./?mode=js-unbundle");
  await upload(page, Buffer.alloc(1024 * 1024 + 1));
  await expect(page.getByRole("alert")).toContainText("JavaScript unbundling accepts inputs up to 1 MiB.");
  await expect(page.locator("html")).not.toHaveAttribute("data-read-size", String(1024 * 1024 + 1));
  await upload(page, Buffer.from([0xff]));
  await expect(page.getByRole("alert")).toContainText("requires UTF-8 text");
  await upload(page, await readFile(bundle));
  await expect(page.getByText("Webpack 5 · 3 modules extracted", { exact: true })).toBeVisible();
});

test("automatic routing opens the uploaded JavaScript bundle", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await upload(page, await readFile(bundle));
  await page.getByRole("button", { name: "Run in Unbundle JavaScript", exact: true }).click();
  await expect(page.getByText("Webpack 5 · 3 modules extracted", { exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("bundle.js");
});

test("JSX and TSX module tags are highlighted as markup in both themes", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-unbundle");
  for (const extension of ["jsx", "tsx"]) {
    const source: string = `const label${extension === "tsx" ? ": string" : ""} = 'ready'; module.exports = <section data-state={label}><span>{label}</span></section>;`;
    await upload(page, `var __webpack_modules__ = {"Widget.${extension}": function(module, exports) {${source}}}; var __webpack_module_cache__ = {};`);
    await expect(page.getByText("Webpack 5 · 1 module extracted", { exact: true })).toBeVisible();
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      const output = page.getByRole("region", { name: "output", exact: true }).locator(".cm-content");
      await expect(output.locator("span").filter({ hasText: /^section$/u })).toHaveCount(2);
      await expect(output.locator("span").filter({ hasText: /^span$/u })).toHaveCount(2);
      expect((await download(page, "Download module")).bytes).toEqual(Buffer.from(source));
    }
  }
});
