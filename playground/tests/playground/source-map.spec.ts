import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";

const originalRoot: URL = new URL("../../../corpus/js/esbuild/src/", import.meta.url);

async function upload(page: Page, text: string | Buffer): Promise<void> {
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "input.map", mimeType: "application/json", buffer: typeof text === "string" ? Buffer.from(text) : text });
}

async function sourceDownload(page: Page): Promise<{ name: string; bytes: Buffer }> {
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download source", exact: true }).click();
  const download = await event;
  const path: string | null = await download.path();
  if (path === null) throw new Error("Source download has no local file");
  return { name: download.suggestedFilename(), bytes: await readFile(path) };
}

test("source maps recover all four original esbuild files byte for byte", async ({ page }): Promise<void> => {
  await page.goto("./?mode=source-map");
  await expect(page.getByText("4 of 4 originals recovered", { exact: true })).toBeVisible();
  for (const name of ["lazy.js", "util.js", "math.js", "index.js"]) {
    await page.getByRole("combobox", { name: "Source file", exact: true }).selectOption(`src/${name}`);
    const download = await sourceDownload(page);
    expect(download.name).toBe(name);
    expect(download.bytes).toEqual(await readFile(new URL(name, originalRoot)));
  }
});

test("indexed maps retain independent roots, empty originals, and missing-source identities", async ({ page }): Promise<void> => {
  await page.goto("./?mode=source-map");
  await upload(page, JSON.stringify({ version: 3, sourceRoot: "not-inherited", sections: [
    { offset: { line: 0, column: 0 }, map: { version: 3, sourceRoot: "src", sources: ["empty.ts", "missing.ts"], sourcesContent: ["", null], mappings: "" } },
    { offset: { line: 10, column: 0 }, map: { version: 3, sourceRoot: "ui", sources: ["entry.tsx"], sourcesContent: ["export const element = <main>Recovered</main>;"], mappings: "" } },
  ] }));
  await expect(page.getByText("2 of 3 originals recovered", { exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "Source file", exact: true }).selectOption("src/empty.ts");
  expect(await sourceDownload(page)).toEqual({ name: "empty.ts", bytes: Buffer.alloc(0) });
  await page.getByRole("combobox", { name: "Source file", exact: true }).selectOption("ui/entry.tsx");
  expect(await sourceDownload(page)).toEqual({ name: "entry.tsx", bytes: Buffer.from("export const element = <main>Recovered</main>;") });
  await page.getByText("Sources without embedded content (1)", { exact: true }).click();
  await expect(page.getByText("src/missing.ts", { exact: true })).toBeVisible();
});

test("inline maps recover source and external references stay inert", async ({ page }): Promise<void> => {
  const requested: string[] = [];
  await page.route("https://example.invalid/**", async (route): Promise<void> => { requested.push(route.request().url()); await route.abort(); });
  await page.goto("./?mode=source-map");
  const map: Buffer = await readFile(new URL("../../../corpus/js/esbuild/bundle.js.map", import.meta.url));
  await upload(page, `{ const answer = 42; }\nthrow new Error('must not run');\n//# sourceMappingURL=data:application/json;base64,${map.toString("base64")}`);
  await expect(page.getByText("4 of 4 originals recovered", { exact: true })).toBeVisible();
  await upload(page, "throw new Error('must not run');\n//# sourceMappingURL=https://example.invalid/app.js.map");
  await expect(page.getByText("Map file required", { exact: true })).toBeVisible();
  await expect(page.getByText("https://example.invalid/app.js.map", { exact: true })).toBeVisible();
  expect(requested).toEqual([]);
  await upload(page, "const value = 42;");
  await expect(page.getByText("No source map found", { exact: true })).toBeVisible();
});

test("source-map size, UTF-8, and offset failures allow the next valid input", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const original: typeof File.prototype.arrayBuffer = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function (this: File): Promise<ArrayBuffer> {
      document.documentElement.setAttribute("data-read-size", String(this.size));
      return original.call(this);
    };
  });
  await page.goto("./?mode=source-map");
  await upload(page, Buffer.alloc(1024 * 1024 + 1));
  await expect(page.getByRole("alert")).toContainText("Source-map recovery accepts inputs up to 1 MiB.");
  await expect(page.locator("html")).not.toHaveAttribute("data-read-size", String(1024 * 1024 + 1));
  for (const input of [Buffer.from([0xff]), Buffer.from("{broken"), Buffer.from('{"version":3,"sections":[{"offset":{"line":4294967295,"column":0},"map":{"version":3,"mappings":"A"}}]}')]) {
    await upload(page, input);
    await expect(page.getByRole("alert")).toBeVisible();
    await page.getByRole("button", { name: "Load sample", exact: true }).click();
    await expect(page.getByText("4 of 4 originals recovered", { exact: true })).toBeVisible();
  }
});

test("source filtering and shortened previews keep complete downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=source-map");
  await page.getByText("Find files", { exact: true }).click();
  await page.getByRole("searchbox", { name: "Filter recovered files", exact: true }).fill("MATH");
  await expect(page.getByRole("combobox", { name: "Source file", exact: true })).toHaveValue("src/math.js");
  expect((await sourceDownload(page)).bytes).toEqual(await readFile(new URL("math.js", originalRoot)));
  await page.getByRole("searchbox", { name: "Filter recovered files", exact: true }).fill("missing-file-name");
  await expect(page.getByText("No files match this search.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download source", exact: true })).toBeDisabled();
  await page.getByRole("searchbox", { name: "Filter recovered files", exact: true }).fill("");
  const original: string = "x".repeat(70_000);
  await upload(page, JSON.stringify({ version: 3, sources: ["large.js"], sourcesContent: [original], mappings: "" }));
  await expect(page.getByText("1 of 1 original recovered", { exact: true })).toBeVisible();
  await expect(page.getByText("Preview shortened. Downloads contain the complete output.", { exact: true })).toBeVisible();
  expect((await sourceDownload(page)).bytes).toEqual(Buffer.from(original));
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.getByRole("button", { name: "JSON report", exact: true })).toHaveAttribute("aria-pressed", "true");
});
