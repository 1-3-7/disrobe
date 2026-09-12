import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const fixture = new URL("../../../crates/disrobe-pass-mobile/tests/fixtures/flutter_symbol_dart_3_12_2/", import.meta.url);

function be(value: number): Buffer {
  const output: Buffer = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function byteList(text: string): Buffer {
  const bytes: Buffer = Buffer.from(text);
  if (bytes.length >= 0x4000) throw new Error("Dart test source exceeds the fixture encoding");
  const length: Buffer = bytes.length < 128 ? Buffer.from([bytes.length]) : Buffer.from([0x80 | (bytes.length >> 8), bytes.length & 255]);
  return Buffer.concat([length, bytes]);
}

function kernel(sources: readonly { readonly uri: string; readonly text: string }[]): Buffer {
  const table: Buffer = Buffer.concat([be(sources.length), ...sources.flatMap((source): Buffer[] => [byteList(source.uri), byteList(source.text), Buffer.from([0, 0, 0])])]);
  const body: Buffer = Buffer.concat([be(0x90abcdef), be(130), table, Buffer.from([0])]);
  return Buffer.concat([body, be(8), ...Array.from({ length: 5 }, (): Buffer => be(0)), be(8 + table.length), be(0), be(0), be(0), be(0), be(body.length + 48)]);
}

test("Dart Kernel routes to individual embedded source downloads", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("symbol_probe.app.dill", fixture)));
  await page.getByRole("button", { name: "Run in Recover Dart Kernel", exact: true }).click({ timeout: 10_000 });
  await expect(page.getByRole("combobox", { name: "Source file", exact: true })).toHaveValue("0");
  await expect(page.locator(".cm-editor")).toContainText("Symbol('shipment.status')");
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("symbol_probe.dart");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The Dart source download has no file");
  expect(await readFile(path)).toEqual(await readFile(new URL("symbol_probe.dart", fixture)));
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText('"format_version": 130');
});

test("Dart Kernel rejects invalid inputs without retaining old source", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dart-kernel");
  await expect(page.locator(".cm-editor")).toContainText("shipment.status");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({
    name: "invalid.dill",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([0x90, 0xab, 0xcd, 0xef, 0, 0, 0, 130]),
  });
  await expect(page.getByRole("alert")).toContainText("Dart Kernel");
  await expect(page.getByRole("combobox", { name: "Source file", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.locator(".cm-editor")).toContainText("shipment.status");
});

test("Dart source records remain separate despite matching basenames", async ({ page }): Promise<void> => {
  const sources = [
    { uri: "disrobe-fixture:///first/probe.dart", text: await readFile(new URL("symbol_probe.dart", fixture), "utf8") },
    { uri: "disrobe-fixture:///second/probe.dart", text: await readFile(new URL("../../../corpus/mobile/flutter/disrobe_sample/disrobe_aot_sample.dart", import.meta.url), "utf8") },
  ];
  await page.goto("./?mode=dart-kernel");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "sources.dill", mimeType: "application/octet-stream", buffer: kernel(sources) });
  const selector = page.getByRole("combobox", { name: "Source file", exact: true });
  await expect(selector.locator("option")).toHaveCount(2);
  for (const [index, source] of sources.entries()) {
    await selector.selectOption(String(index));
    const event = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download output", exact: true }).click();
    const download = await event;
    expect(download.suggestedFilename()).toBe("probe.dart");
    const path: string | null = await download.path();
    if (path === null) throw new Error("The selected Dart source download has no file");
    expect(await readFile(path, "utf8")).toBe(source.text);
  }
});

test("Dart empty and absent source records have distinct output states", async ({ page }): Promise<void> => {
  await page.goto("./?mode=dart-kernel");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "no-source.dill", mimeType: "application/octet-stream", buffer: kernel([]) });
  await expect(page.getByText("No embedded source recovered", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Dart source", exact: true })).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("button", { name: "JSON report", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("combobox", { name: "Source file", exact: true })).toHaveCount(0);
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "empty-source.dill", mimeType: "application/octet-stream", buffer: kernel([{ uri: "disrobe-fixture:///empty.dart", text: "" }]) });
  await expect(page.getByText("This source entry is empty.", { exact: true })).toBeVisible();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await event;
  expect(download.suggestedFilename()).toBe("empty.dart");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The empty Dart source download has no file");
  expect((await readFile(path)).length).toBe(0);
});
