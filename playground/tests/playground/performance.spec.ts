import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

type VitalName = "LCP" | "CLS" | "INP";
interface VitalRecord {
  readonly name: VitalName;
  readonly value: number;
  readonly id: string;
}

declare global {
  interface Window {
    reportWebVital(name: string, value: number, id: string, url: string): Promise<void>;
  }
}

function observeVitals(vitals: Pick<typeof import("web-vitals"), "onLCP" | "onCLS" | "onINP">): void {
  const report = (metric: { name: string; value: number; id: string }): void => {
    void window.reportWebVital(metric.name, metric.value, metric.id, window.location.href);
  };
  vitals.onLCP(report, { reportAllChanges: true });
  vitals.onCLS(report, { reportAllChanges: true });
  vitals.onINP(report, { reportAllChanges: true });
}

test("analysis interactions meet the browser performance budget", async ({ page }, testInfo): Promise<void> => {
  const received: Map<VitalName, VitalRecord> = new Map();
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  await page.exposeFunction("reportWebVital", (name: string, value: number, id: string, url: string): void => {
    if (new URL(url).searchParams.get("mode") !== "php-detect") return;
    if ((name !== "LCP" && name !== "CLS" && name !== "INP") || !Number.isFinite(value)) {
      throw new Error("Web Vitals returned an invalid measurement");
    }
    received.set(name, { name, value, id });
  });
  const script: string = await readFile(fileURLToPath(new URL("../../node_modules/web-vitals/dist/web-vitals.iife.js", import.meta.url)), "utf8");
  await page.addInitScript({ content: `${script}\n;(${observeVitals.toString()})(webVitals);` });
  const devtools = await page.context().newCDPSession(page);
  await devtools.send("Emulation.setCPUThrottlingRate", { rate: 4 });
  await devtools.send("Network.setCacheDisabled", { cacheDisabled: true });
  const started: number = Date.now();
  await page.goto("./?mode=php-detect");
  const completed = page.getByRole("heading", { name: "output", exact: true }).locator("../..").getByText("php_detect", { exact: true });
  await expect(completed).toBeVisible();
  const readyMs: number = Date.now() - started;
  await page.locator(".cm-content[contenteditable=true]").fill("<?php echo 42;");
  await page.getByRole("button", { name: "Run analysis", exact: true }).click();
  await expect(completed).toBeVisible();
  await page.locator('label[title="Light"]').click();
  await page.locator('label[title="Dark"]').click();
  await page.screenshot({ path: testInfo.outputPath("performance.png") });
  expect(errors).toEqual([]);
  await page.goto("about:blank");
  await expect.poll((): number => received.size).toBe(3);
  const reportPath: string = testInfo.outputPath("performance.json");
  await writeFile(reportPath, JSON.stringify({
    captured_at: new Date().toISOString(),
    project: testInfo.project.name,
    viewport: testInfo.project.use.viewport,
    cpu_slowdown: 4,
    cache: "disabled",
    transport: "loopback Vite preview, unthrottled",
    ready_ms: readyMs,
    metrics: [...received.values()],
  }, null, 2));
  await testInfo.attach("performance", { path: reportPath, contentType: "application/json" });
  expect(received.get("LCP")?.value).toBeLessThan(4_000);
  expect(received.get("CLS")?.value).toBeLessThan(0.25);
  expect(received.get("INP")?.value).toBeLessThan(500);
});
