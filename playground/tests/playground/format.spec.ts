import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import { javascript } from "@codemirror/lang-javascript";
import type { Tree } from "@lezer/common";

async function upload(page: Page, source: string | Buffer, name = "input.js"): Promise<void> {
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name, mimeType: "text/plain", buffer: typeof source === "string" ? Buffer.from(source) : source });
}

async function download(page: Page): Promise<{ filename: string; source: string }> {
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download formatted source", exact: true }).click();
  const artifact = await event;
  const path: string | null = await artifact.path();
  if (path === null) throw new Error("Formatted source has no download path");
  return { filename: artifact.suggestedFilename(), source: await readFile(path, "utf8") };
}

function syntaxTree(source: string, filename: string): Tree {
  const tree: Tree = javascript({ jsx: filename.endsWith("x"), typescript: /\.tsx?$/.test(filename) }).language.parser.parse(source);
  const errors: number[] = [];
  tree.iterate({ enter(node): void { if (node.type.isError) errors.push(node.from); } });
  expect(errors).toEqual([]);
  return tree;
}

test("formatting preserves JavaScript expressions and return newlines", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-format");
  await expect(page.getByRole("button", { name: "Download formatted source", exact: true })).toBeVisible();
  const source = "function read(){return\n{value:1}}const ratio=8/2/2;const pattern=/a+/giu;const exact=9007199254740993n;const wrap=(value)=>({value});";
  await upload(page, source);
  const artifact = await download(page);
  expect(artifact.filename).toBe("formatted.js");
  const tree: Tree = syntaxTree(artifact.source, artifact.filename);
  const returns: string[] = [];
  tree.iterate({ enter(node): void { if (node.name === "ReturnStatement") returns.push(artifact.source.slice(node.from, node.to)); } });
  expect(returns).toEqual(["return;"]);
  for (const token of ["8 / 2 / 2", "/a+/giu", "9007199254740993n", "=> ({ value })"]) expect(artifact.source).toContain(token);
  await upload(page, artifact.source);
  expect((await download(page)).source).toBe(artifact.source);
});

test("all four source grammars retain declarations and colored output", async ({ page }): Promise<void> => {
  const samples = [
    ["js", "export const value=42;", "value"],
    ["jsx", "export const Badge=({value})=><span title=\"Value\">{value}</span>;", "span"],
    ["ts", "export interface Item{id:number}export const item:Item={id:42};", "interface Item"],
    ["tsx", "type Props={value:number};export const Badge=({value}:Props)=><span title=\"Value\">{value}</span>;", "type Props"],
  ] as const;
  for (const [language, source, token] of samples) {
    await page.goto(`./?mode=${language}-format`);
    await upload(page, source, `input.${language}`);
    const artifact = await download(page);
    expect(artifact.filename).toBe(`formatted.${language}`);
    syntaxTree(artifact.source, artifact.filename);
    expect(artifact.source).toContain(token);
    if (language.endsWith("x")) expect(artifact.source).toContain("</span>");
    for (const theme of ["Dark", "Light"]) {
      await page.locator(`label[title="${theme}"]`).click();
      const colors: string[] = await page.getByRole("region", { name: "output", exact: true }).locator(".cm-content").evaluate((node): string[] => [...new Set(Array.from(node.querySelectorAll("span"), (span): string => getComputedStyle(span).color))]);
      expect(colors.length).toBeGreaterThanOrEqual(3);
    }
  }
});

test("formatter rejects invalid syntax and recovers on the next input", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-format");
  for (const source of ["const =;", "const broken=/[/;", "const value: number = 42;"]) {
    await upload(page, source);
    await expect(page.getByRole("alert")).toContainText("syntax");
    if (source === "const =;") {
      const positions = await page.getByRole("alert").locator("p").evaluate((node): { token: { x: number; y: number }; caret: { x: number; y: number } } => {
        const text: ChildNode | null = node.firstChild;
        if (!(text instanceof Text)) throw new Error("Syntax error has no text");
        const point = (character: string): { x: number; y: number } => {
          const offset: number = text.data.lastIndexOf(character);
          if (offset < 0) throw new Error(`Syntax error has no ${character}`);
          const range: Range = document.createRange();
          range.setStart(text, offset);
          range.setEnd(text, offset + 1);
          const bounds: DOMRect = range.getBoundingClientRect();
          return { x: bounds.x, y: bounds.y };
        };
        return { token: point("="), caret: point("^") };
      });
      expect(positions.caret.x).toBeCloseTo(positions.token.x, 0);
      expect(positions.caret.y).toBeGreaterThan(positions.token.y);
    }
    await expect(page.getByRole("button", { name: "Download formatted source", exact: true })).toHaveCount(0);
  }
  await upload(page, Buffer.from([0xff]));
  await expect(page.getByRole("alert")).toContainText("UTF-8");
  await upload(page, "const value=42;");
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect((await download(page)).source).toBe("const value = 42;\n");
  await upload(page, "return 42;const same=1;const same=2;");
  expect((await download(page)).source).toBe("return 42;\nconst same = 1;\nconst same = 2;\n");
});

test("formatter bounds uploads and retains comments and complete downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-format");
  await upload(page, " ".repeat(1024 * 1024 + 1));
  await expect(page.getByRole("alert")).toContainText("1 MiB");
  const literal: string = "x".repeat(70_000);
  await upload(page, `/*! Licensed example */\n'use strict';export const value='${literal}';`);
  const artifact = await download(page);
  expect(artifact.source).toContain("/*! Licensed example */");
  expect(artifact.source).toContain('"use strict";');
  expect(artifact.source).toContain(literal);
  syntaxTree(artifact.source, artifact.filename);
  await expect(page.getByText("Preview shortened. Downloads contain the complete output.", { exact: true })).toBeVisible();
});

test("deep source failure restarts the formatter worker", async ({ page }): Promise<void> => {
  await page.goto("./?mode=js-format");
  await upload(page, `${"(".repeat(40_000)}value${")".repeat(40_000)};`);
  await expect(page.getByRole("alert")).toContainText("too deeply nested");
  await upload(page, "const value=42;");
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect((await download(page)).source).toBe("const value = 42;\n");
});
