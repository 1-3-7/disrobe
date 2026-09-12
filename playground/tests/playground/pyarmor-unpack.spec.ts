import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";

const wrapper: URL = new URL("../../../corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py", import.meta.url);
const runtime: URL = new URL("../../../corpus/python/pyarmor/v9_latest_925/default/pyarmor_runtime_000000/pyarmor_runtime.pyd", import.meta.url);

test("PyArmor rejects oversized file selections before reading their contents", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const original: typeof File.prototype.arrayBuffer = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function (this: File): Promise<ArrayBuffer> {
      document.documentElement.setAttribute("data-last-file-read", this.name);
      return original.call(this);
    };
  });
  await page.goto("./?mode=pyarmor-unpack");
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles({ name: "oversized-runtime.pyd", mimeType: "application/octet-stream", buffer: Buffer.alloc(16 * 1024 * 1024 + 1) });
  await expect(page.getByRole("alert")).toContainText("PyArmor runtimes must be at most 16 MiB.");
  await expect(page.locator("html")).not.toHaveAttribute("data-last-file-read", "oversized-runtime.pyd");
  await expect(page.getByRole("button", { name: "Download marshal", exact: true })).toHaveCount(0);
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "oversized-wrapper.py", mimeType: "text/x-python", buffer: Buffer.alloc(1024 * 1024 + 1) });
  await expect(page.getByRole("alert")).toContainText("PyArmor wrappers must be at most 1 MiB.");
  await expect(page.locator("html")).not.toHaveAttribute("data-last-file-read", "oversized-wrapper.py");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(wrapper));
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
});

test("a user wrapper requires an explicit runtime and clears stale sample output", async ({ page }): Promise<void> => {
  await page.goto("./?mode=pyarmor-unpack");
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(wrapper));
  await expect(page.getByText("Matching runtime required", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run analysis", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Download marshal", exact: true })).toHaveCount(0);
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear runtime", exact: true }).click();
  await expect(page.getByRole("button", { name: "Download marshal", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Run analysis", exact: true })).toBeDisabled();
});

test("an immediate edited-wrapper run retains only an explicitly chosen runtime", async ({ page }): Promise<void> => {
  await page.goto("./?mode=pyarmor-unpack");
  const parsed = page.getByText("Marshal code object parsed", { exact: true });
  await expect(parsed).toBeVisible();
  const input = page.locator(".cm-content[contenteditable=true]");
  const wrapperSource: string = await readFile(wrapper, "utf8");
  let editNumber: number = 0;
  const editAndRun = async (): Promise<void> => {
    const source: string = `${wrapperSource}\n# keyboard edit ${++editNumber}`;
    await input.click();
    await page.keyboard.press("ControlOrMeta+A");
    await input.evaluate((element: Element, text: string): void => {
      if (!document.execCommand("insertText", false, text)) throw new Error("Browser edit was rejected");
      const options: KeyboardEventInit = { key: "Enter", code: "Enter", keyCode: 13, ctrlKey: true, bubbles: true, cancelable: true };
      element.dispatchEvent(new KeyboardEvent("keydown", options));
      element.dispatchEvent(new KeyboardEvent("keyup", options));
    }, source);
  };
  await editAndRun();
  await expect(page.getByText("Matching runtime required", { exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata").getByText("idle", { exact: true })).toBeVisible();
  await expect(parsed).toHaveCount(0);
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
  await expect(parsed).toBeVisible();
  await editAndRun();
  await expect(parsed).toBeVisible();
  await expect(page.getByRole("button", { name: "Run analysis", exact: true })).toBeEnabled();
});

test("PyArmor unpacks paired files into a parsed marshal code object", async ({ page }): Promise<void> => {
  await page.goto("./?mode=pyarmor-unpack");
  await expect(page.getByRole("heading", { name: "Unpack PyArmor", exact: true })).toBeVisible({ timeout: 10_000 });
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(wrapper));
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await expect(page.getByText("Python 3.14", { exact: true })).toBeVisible();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download marshal", exact: true }).click();
  const download = await event;
  expect(download.suggestedFilename()).toBe("pyarmor-module.marshal");
  const path: string | null = await download.path();
  if (path === null) throw new Error("Missing marshal download");
  const bytes: Buffer = await readFile(path);
  expect(bytes[0] === 0x63 || bytes[0] === 0xe3).toBe(true);
  for (const text of ["add", "classify", "Counter", "increment", "main", "disrobe-vmc-oracle-12345", "negative", "zero", "positive"]) {
    expect(bytes.includes(Buffer.from(text))).toBe(true);
  }
});

async function holdPyarmorReads(page: Page): Promise<void> {
  await page.addInitScript((): void => {
    const original: typeof File.prototype.arrayBuffer = File.prototype.arrayBuffer;
    const held: Map<string, () => void> = new Map();
    File.prototype.arrayBuffer = function (this: File): Promise<ArrayBuffer> {
      const name: string = this.name;
      const bytes: Promise<ArrayBuffer> = original.call(this);
      if (name !== "held-wrapper.py" && name !== "held-runtime.pyd") return bytes;
      return bytes.then((buffer: ArrayBuffer): Promise<ArrayBuffer> => new Promise((resolve): void => {
        held.set(name, (): void => {
          held.delete(name);
          resolve(buffer);
          document.documentElement.setAttribute("data-pyarmor-read-released", name);
        });
        document.documentElement.setAttribute("data-pyarmor-read-held", [...held.keys()].join(" "));
      }));
    };
    window.addEventListener("release-pyarmor-read", (event: Event): void => {
      if (event instanceof CustomEvent && typeof event.detail === "string") held.get(event.detail)?.();
    });
  });
}

async function releasePyarmorRead(page: Page, name: string): Promise<void> {
  await expect(page.locator("html")).toHaveAttribute("data-pyarmor-read-held", new RegExp(name.replaceAll(".", "\\.")));
  await page.evaluate((fileName: string): void => {
    window.dispatchEvent(new CustomEvent("release-pyarmor-read", { detail: fileName }));
  }, name);
  await expect(page.locator("html")).toHaveAttribute("data-pyarmor-read-released", name);
}

test("a completed runtime selection survives replacement of its still-reading wrapper", async ({ page }): Promise<void> => {
  await holdPyarmorReads(page);
  await page.goto("./?mode=pyarmor-unpack");
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear runtime", exact: true }).click();
  const wrapperBytes: Buffer = await readFile(wrapper);
  const runtimeBytes: Buffer = await readFile(runtime);
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles({ name: "held-runtime.pyd", mimeType: "application/octet-stream", buffer: runtimeBytes });
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "held-wrapper.py", mimeType: "text/x-python", buffer: wrapperBytes });
  await releasePyarmorRead(page, "held-runtime.pyd");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "replacement-wrapper.py", mimeType: "text/x-python", buffer: wrapperBytes });
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("replacement-wrapper.py");
  await expect(page.getByText("held-runtime.pyd", { exact: true })).toBeVisible();
  await releasePyarmorRead(page, "held-wrapper.py");
  await expect(page.getByTestId("input-metadata")).toContainText("replacement-wrapper.py");
  await expect(page.getByText("held-runtime.pyd", { exact: true })).toBeVisible();
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
});

test("a completed wrapper selection survives replacement of its still-reading runtime", async ({ page }): Promise<void> => {
  await holdPyarmorReads(page);
  await page.goto("./?mode=pyarmor-unpack");
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  const wrapperBytes: Buffer = await readFile(wrapper);
  const runtimeBytes: Buffer = await readFile(runtime);
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles({ name: "held-wrapper.py", mimeType: "text/x-python", buffer: wrapperBytes });
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles({ name: "held-runtime.pyd", mimeType: "application/octet-stream", buffer: runtimeBytes });
  await releasePyarmorRead(page, "held-wrapper.py");
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles({ name: "replacement-runtime.pyd", mimeType: "application/octet-stream", buffer: runtimeBytes });
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  await expect(page.getByTestId("input-metadata")).toContainText("held-wrapper.py");
  await expect(page.getByText("replacement-runtime.pyd", { exact: true })).toBeVisible();
  await releasePyarmorRead(page, "held-runtime.pyd");
  await expect(page.getByTestId("input-metadata")).toContainText("held-wrapper.py");
  await expect(page.getByText("replacement-runtime.pyd", { exact: true })).toBeVisible();
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
});

test("PyArmor rejects overflowing runtime offsets and reuses the worker for valid recovery", async ({ page }): Promise<void> => {
  const runtimeBytes: Buffer = await readFile(runtime);
  const anchor: number = runtimeBytes.indexOf(Buffer.from("pyarmor-vax"));
  expect(anchor).toBeGreaterThanOrEqual(0x2c);
  const descriptor: number = anchor - 0x2c;
  expect(runtimeBytes.readUInt32LE(descriptor + 0x4c)).toBe(32);
  let workerStarts: number = 0;
  const errors: string[] = [];
  page.on("worker", (): void => { workerStarts += 1; });
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  await page.goto("./?mode=pyarmor-unpack");
  await page.getByLabel("Choose an input file", { exact: true }).setInputFiles(fileURLToPath(wrapper));
  await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
  await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
  const initialWorkerStarts: number = workerStarts;
  expect(initialWorkerStarts).toBeGreaterThan(0);

  for (const field of [0x48, 0x50, 0x58]) {
    const malformed: Buffer = Buffer.from(runtimeBytes);
    malformed.writeUInt32LE(0xffff_ffff, descriptor + field);
    await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles({
      name: `runtime-offset-${field.toString(16)}.pyd`,
      mimeType: "application/octet-stream",
      buffer: malformed,
    });
    await expect(page.getByRole("alert")).toContainText("PyArmor module:");
    await expect(page.getByRole("alert")).toContainText("runtime data offset overflow");
    await expect(page.getByText("Marshal code object parsed", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Download marshal", exact: true })).toHaveCount(0);
    expect(workerStarts).toBe(initialWorkerStarts);

    await page.getByLabel("Choose PyArmor runtime", { exact: true }).setInputFiles(fileURLToPath(runtime));
    await expect(page.getByText("Marshal code object parsed", { exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByText("Python 3.14", { exact: true })).toBeVisible();
    const pending = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download marshal", exact: true }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe("pyarmor-module.marshal");
    const path: string | null = await download.path();
    if (path === null) throw new Error("Missing recovered marshal download after runtime rejection");
    const bytes: Buffer = await readFile(path);
    expect(bytes[0] === 0x63 || bytes[0] === 0xe3).toBe(true);
    expect(bytes.includes(Buffer.from("disrobe-vmc-oracle-12345"))).toBe(true);
    expect(workerStarts).toBe(initialWorkerStarts);
    expect(errors).toEqual([]);
  }
});
