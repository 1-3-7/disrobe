import { expect, test } from "@playwright/test";

declare global {
  interface Window {
    engineWorkerStarts?: number;
  }
}

test("a trapped analysis engine is discarded before the next recovery", async ({ page }): Promise<void> => {
  await page.addInitScript((): void => {
    const NativeWorker: typeof Worker = window.Worker;
    window.engineWorkerStarts = 0;
    window.Worker = class extends NativeWorker {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        window.engineWorkerStarts = (window.engineWorkerStarts ?? 0) + 1;
      }
    };
  });
  let trapped: boolean = false;
  await page.route(/\/disrobe\.worker-[^/]+\.js$/u, async (route): Promise<void> => {
    if (trapped) {
      await route.continue();
      return;
    }
    trapped = true;
    const response = await route.fetch();
    const source: string = await response.text();
    const inject: string = `
const originalInstantiate = WebAssembly.instantiateStreaming.bind(WebAssembly);
WebAssembly.instantiateStreaming = async (...args) => {
  const loaded = await originalInstantiate(...args);
  const trapModule = new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,7,8,1,4,116,114,97,112,0,0,10,5,1,3,0,0,11]));
  const trap = new WebAssembly.Instance(trapModule).exports.trap;
  return { module: loaded.module, instance: { exports: { ...loaded.instance.exports, php_detect: trap } } };
};
`;
    await route.fulfill({ response, body: inject + source });
  });
  await page.goto("./?mode=php-detect");
  await expect(page.getByRole("alert")).toContainText("unreachable");
  await expect.poll(() => page.evaluate((): number => window.engineWorkerStarts ?? 0)).toBe(1);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true })).toBeVisible();
  expect(await page.evaluate((): number => window.engineWorkerStarts ?? 0)).toBe(2);
  await expect(page.getByRole("alert")).toHaveCount(0);
});
