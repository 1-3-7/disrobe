import { expect, test } from "@playwright/test";

declare global {
  interface Window {
    analysisWorkers?: Worker[];
  }
}

test.beforeEach(async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const NativeWorker: typeof Worker = window.Worker;
    let created: number = 0;
    const registry: Window & { analysisWorkers: Worker[] } = Object.assign(window, { analysisWorkers: [] as Worker[] });
    window.Worker = class extends NativeWorker {
      readonly paused: boolean;

      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        this.paused = created++ === 0;
        registry.analysisWorkers.push(this);
      }

      override postMessage(message: unknown, transferOrOptions?: Transferable[] | StructuredSerializeOptions): void {
        if (this.paused) return;
        if (Array.isArray(transferOrOptions)) {
          super.postMessage(message, transferOrOptions);
        } else {
          super.postMessage(message, transferOrOptions);
        }
      }
    };
  });
});

test("stopping pending work allows a fresh analysis", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  await page.getByRole("button", { name: "Stop analysis", exact: true }).click();
  await expect(page.getByText("Load an artifact or run the current sample to see recovered output here.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
});

test("an unresponsive worker times out and the next sample recovers", async ({ page }): Promise<void> => {
  await page.clock.install();
  await page.goto("./?mode=php-detect");
  await expect(page.getByRole("button", { name: "Stop analysis", exact: true })).toBeVisible();
  await page.clock.fastForward(30_001);
  await expect(page.getByRole("alert")).toContainText("Analysis exceeded 30 seconds");
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
});

test("a worker crash reports an error and permits a fresh analysis", async ({ page }): Promise<void> => {
  await page.goto("./?mode=php-detect");
  await expect(page.getByRole("button", { name: "Stop analysis", exact: true })).toBeVisible();
  await page.evaluate((): void => {
    const worker: Worker | undefined = window.analysisWorkers?.[0];
    if (worker === undefined) throw new Error("Analysis worker was not created");
    worker.dispatchEvent(new ErrorEvent("error", { message: "Analysis worker crashed", cancelable: true }));
  });
  await expect(page.getByRole("alert")).toContainText("Analysis worker crashed");
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
});

test("oversized files are rejected before reading their contents", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    Object.defineProperty(File.prototype, "size", { get: (): number => 64 * 1024 * 1024 + 1 });
    File.prototype.arrayBuffer = (): Promise<ArrayBuffer> => Promise.reject(new Error("Oversized file contents were read"));
  });
  await page.goto("./?mode=php-detect");
  await page.getByRole("button", { name: "Stop analysis", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({ name: "oversized.php", mimeType: "text/plain", buffer: Buffer.from("<?php echo 42;") });
  await expect(page.getByRole("alert")).toContainText("The playground accepts inputs up to 64 MiB");
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
});
