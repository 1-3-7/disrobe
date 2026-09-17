import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { ALL_MODES } from "../../src/lib/modes";

test("every shipped analysis entry has a runnable interface", async ({ page }): Promise<void> => {
  const bytes: Buffer = await readFile(new URL("../../src/wasm/disrobe_wasm.wasm", import.meta.url));
  const module: WebAssembly.Module = new WebAssembly.Module(Uint8Array.from(bytes));
  const exports: string[] = WebAssembly.Module.exports(module)
    .filter((entry): boolean => entry.kind === "function" && !/^(?:disrobe_|__getrandom_|rust_(?:lzma|zstd)_wasm_shim_)/u.test(entry.name))
    .map((entry): string => entry.name).sort();
  const modes: string[] = ALL_MODES.flatMap((mode): string[] => mode.entry === null ? [] : [mode.entry]).sort();
  expect([...modes, "phar_extract"].sort()).toEqual([...exports, "js_format", "jsx_format", "ts_format", "tsx_format"].sort());
  await page.goto("./?mode=phar");
  await page.getByRole("combobox", { name: "Archive member", exact: true }).selectOption({ label: "lib/math.php" });
  await page.getByRole("button", { name: "Extract member", exact: true }).click();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download member", exact: true }).click();
  const download = await downloadEvent;
  const path: string | null = await download.path();
  if (path === null) throw new Error("The PHAR extraction interface has no download");
  expect(await readFile(path)).toEqual(await readFile(new URL("../../../corpus/php/phar-bz2/src/lib/math.php", import.meta.url)));
});

for (const [id, title] of [["detect", "Identify Format"], ["pyarmor-detect", "Inspect PyArmor"], ["pyarmor-classify", "Classify PyArmor"], ["swift-objc", "Inspect Swift / Objective-C"]] as const) {
  test(`${id} opens directly with a working sample`, async ({ page }): Promise<void> => {
    await page.goto(`./?mode=${id}`);
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Download output", exact: true })).toBeVisible();
  });
}

test("automatic routing opens the PyArmor classifier with the uploaded file", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../public/samples/pyarmor_known_plaintext.py", import.meta.url)));
  await page.getByRole("button", { name: "Run in Classify PyArmor", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Classify PyArmor", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("pyarmor_known_plaintext.py");
  const output = page.getByRole("region", { name: "output", exact: true });
  await expect(output).toContainText("PyArmor 9");
  await expect(output).toContainText("StaticRecoverable");
  await expect(page.locator(".cm-content[contenteditable=true]")).toContainText("__pyarmor__");
});

test("Swift inspection exposes named types and downloads the complete metadata", async ({ page }): Promise<void> => {
  await page.goto("./?mode=swift-objc");
  await expect(page.getByRole("heading", { name: "SwiftHello.LoginViewController", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "SwiftHello.AuthenticationService", exact: true })).toBeVisible();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download output", exact: true }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("swift-objc.json");
  const path: string | null = await download.path();
  expect(path).not.toBeNull();
  if (path === null) throw new Error("The report download has no file");
  const report: unknown = JSON.parse(await readFile(path, "utf8"));
  expect(report).toMatchObject({ ok: true, format: "swift-objc", slice_count: 1, report: { slices: [expect.objectContaining({ cpu_label: "arm64", metadata_summary: expect.objectContaining({ swift_nominal_types: 2, objc_classes: 2 }) })] } });
});

test("automatic routing recommends Swift inspection for the compiled Mach-O sample", async ({ page }): Promise<void> => {
  await page.goto("./?mode=auto-route");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(new URL("../../public/samples/SwiftHello", import.meta.url)));
  await page.getByRole("button", { name: "Run in Inspect Swift / Objective-C", exact: true }).click();
  await expect(page.getByRole("heading", { name: "SwiftHello.LoginViewController", exact: true })).toBeVisible();
});

test("Swift inspection explains an unsupported input and can load its sample again", async ({ page }): Promise<void> => {
  await page.goto("./?mode=swift-objc");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("ordinary text") });
  await expect(page.getByRole("status").filter({ hasText: "Choose a Mach-O binary or an IPA package" })).toBeVisible();
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "SwiftHello.LoginViewController", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Choose a Mach-O binary or an IPA package" })).toHaveCount(0);
});
