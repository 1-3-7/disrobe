import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const fixture: URL = new URL("../../../crates/disrobe-pass-go/tests/fixtures/goembed/goembed_elf32_le", import.meta.url);

function elfText(bytes: Buffer, sectionName: string): { readonly address: number; readonly bytes: Buffer } {
  expect(bytes.subarray(0, 6).toString("hex")).toBe("7f454c460101");
  const offset: number = bytes.readUInt32LE(32);
  const size: number = bytes.readUInt16LE(46);
  const count: number = bytes.readUInt16LE(48);
  const stringsHeader: number = offset + bytes.readUInt16LE(50) * size;
  const namesStart: number = bytes.readUInt32LE(stringsHeader + 16);
  const names: Buffer = bytes.subarray(namesStart, namesStart + bytes.readUInt32LE(stringsHeader + 20));
  for (let index: number = 0; index < count; index += 1) {
    const header: number = offset + index * size;
    const nameStart: number = bytes.readUInt32LE(header);
    const nameEnd: number = names.indexOf(0, nameStart);
    expect(nameEnd).toBeGreaterThanOrEqual(nameStart);
    if (names.subarray(nameStart, nameEnd).toString("utf8") !== sectionName) continue;
    const start: number = bytes.readUInt32LE(header + 16);
    const end: number = start + bytes.readUInt32LE(header + 20);
    expect(end).toBeLessThanOrEqual(bytes.length);
    return { address: bytes.readUInt32LE(header + 12), bytes: bytes.subarray(start, end) };
  }
  throw new Error(`Fixture is missing ${sectionName}`);
}

test("Go metadata retains a build-only result when its function table is absent", async ({ page }): Promise<void> => {
  const bytes: Buffer = await readFile(fixture);
  const table = elfText(bytes, ".gopclntab");
  expect(table.bytes.length).toBeGreaterThan(32);
  table.bytes.fill(0);
  await page.goto("./?mode=go");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "build-only.elf", mimeType: "application/octet-stream", buffer: bytes });
  const metadata = page.getByRole("region", { name: "Go metadata", exact: true });
  await expect(metadata.getByText("Not found", { exact: true })).toHaveCount(3);
  await expect(metadata.getByText("embedwide", { exact: true }).first()).toBeVisible();
  await metadata.getByRole("button", { name: "Types", exact: true }).click();
  await expect(metadata.getByText("Runtime type metadata was not located.", { exact: true })).toBeVisible();
  await metadata.getByRole("button", { name: "Functions", exact: true }).click();
  await expect(metadata.getByText("No Go function table was found. Build information is available separately.", { exact: true })).toBeVisible();
  await metadata.getByRole("button", { name: "JSON report", exact: true }).click();
  const event = page.waitForEvent("download");
  await metadata.getByRole("button", { name: "Download output", exact: true }).click();
  const path: string | null = await (await event).path();
  if (path === null) throw new Error("Build-only JSON download is missing");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({ ok: true, symbols: null, types: null, module: null, build_info: { go_version: "go1.26.5", path: "embedwide" } });
});

test("Stripped Go function addresses match the paired nm reference", async ({ page }): Promise<void> => {
  const base: URL = new URL("../../../crates/disrobe-pass-go/tests/fixtures/", import.meta.url);
  const [normal, stripped, nm]: [Buffer, Buffer, string] = await Promise.all([
    readFile(new URL("bench_generics_linux_386", base)),
    readFile(new URL("bench_generics_linux_386_stripped", base)),
    readFile(new URL("bench_generics_linux_386.nm.txt", base), "utf8"),
  ]);
  expect(elfText(normal, ".text")).toEqual(elfText(stripped, ".text"));
  const expected: { readonly name: string; readonly address: string }[] = nm.split(/\r?\n/).flatMap((line): { readonly name: string; readonly address: string }[] => {
    const match: RegExpExecArray | null = /^\s*([0-9a-f]+)\s+[Tt]\s+(main\..+|type:\.eq\.main\..+)$/.exec(line);
    return match?.[1] !== undefined && match[2] !== undefined ? [{ name: match[2], address: `0x${BigInt(`0x${match[1]}`).toString(16)}` }] : [];
  });
  expect(expected.length).toBe(14);
  await page.goto("./?mode=go");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "generics.elf", mimeType: "application/octet-stream", buffer: stripped });
  await expect(page.getByTestId("input-metadata")).toContainText("generics.elf");
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  const event = page.waitForEvent("download");
  await expect(page.getByRole("button", { name: "Download output", exact: true })).toBeInViewport({ ratio: 1 });
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const path: string | null = await (await event).path();
  if (path === null) throw new Error("Stripped Go JSON download is missing");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({ symbols: { functions: expect.arrayContaining(expected.map((value) => expect.objectContaining(value))) } });
});

test("Go executables route to build information and function metadata", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(fixture));
  await page.getByRole("button", { name: "Run in Inspect Go", exact: true }).click({ timeout: 10_000 });
  await expect(page.getByText("go1.26.5", { exact: true })).toBeVisible();
  await page.getByRole("searchbox", { name: "Find a function", exact: true }).fill("main.main");
  await expect(page.getByRole("button", { name: "main.main", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Build info", exact: true }).click();
  await expect(page.getByText("embedwide", { exact: true }).first()).toBeVisible();
  await page.getByRole("button", { name: "JSON report", exact: true }).click();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await event;
  expect(download.suggestedFilename()).toBe("go-metadata.json");
  const path: string | null = await download.path();
  if (path === null) throw new Error("The Go metadata report has no download");
  const result: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(result).toMatchObject({
    ok: true,
    format: "go",
    build_info: {
      go_version: "go1.26.5",
      path: "embedwide",
      settings: { GOOS: "linux", GOARCH: "386", CGO_ENABLED: "0" },
    },
  });
});

test("Go function and type searches paginate and stay independent", async ({ page }): Promise<void> => {
  await page.goto("./?mode=go");
  await expect(page.getByRole("searchbox", { name: "Find a function", exact: true })).toBeInViewport({ ratio: 1 });
  const functions = page.getByRole("group", { name: "Go functions", exact: true });
  await expect(functions.getByRole("button")).toHaveCount(20);
  const first: string | null = await functions.getByRole("button").first().textContent();
  await page.getByRole("button", { name: "Next function page", exact: true }).click();
  await expect(functions.getByRole("button").first()).not.toHaveText(first ?? "");
  await page.getByRole("button", { name: "Previous function page", exact: true }).click();
  await expect(functions.getByRole("button").first()).toHaveText(first ?? "");
  await page.getByRole("searchbox", { name: "Find a function", exact: true }).fill("main.main");
  await functions.getByRole("button", { name: "main.main", exact: true }).click();
  await expect(functions.getByRole("button", { name: "main.main", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Types", exact: true }).click();
  const types = page.getByRole("group", { name: "Go types", exact: true });
  await expect(page.getByRole("searchbox", { name: "Find a type", exact: true })).toHaveValue("");
  await expect(types.getByRole("button")).toHaveCount(20);
  await page.getByRole("searchbox", { name: "Find a type", exact: true }).fill("no-such-go-type-7256");
  await expect(page.getByText("No matching types.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Next type page", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Functions", exact: true }).click();
  await expect(page.getByRole("searchbox", { name: "Find a function", exact: true })).toHaveValue("");
  await expect(functions.getByRole("button")).toHaveCount(20);
});

test("Go inspection clears stale metadata after invalid input and reloads the sample", async ({ page }): Promise<void> => {
  await page.goto("./?mode=go");
  await expect(page.getByRole("region", { name: "Go metadata", exact: true })).toBeVisible();
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({
    name: "truncated.elf",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
  });
  await expect(page.getByRole("alert")).toContainText("Go metadata:");
  await expect(page.getByRole("region", { name: "Go metadata", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByText("go1.26.5", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});
