import { defineConfig } from "@playwright/test";

const playgroundURL: string = new URL(process.env["PLAYGROUND_BASE"] ?? "/", "http://127.0.0.1:8843").href;

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",
  timeout: 20_000,
  workers: 1,
  retries: 0,
  maxFailures: 1,
  use: { colorScheme: "light" },
  projects: [
    { name: "docs-desktop", testMatch: "**/tests/docs/*.spec.ts", use: { baseURL: "http://127.0.0.1:8841", viewport: { width: 1440, height: 1000 } } },
    { name: "docs-mobile", testMatch: "**/tests/docs/*.spec.ts", use: { baseURL: "http://127.0.0.1:8841", viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
    { name: "playground-desktop", testMatch: "**/tests/playground/*.spec.ts", use: { baseURL: playgroundURL, viewport: { width: 1440, height: 1000 } } },
    { name: "playground-mobile", testMatch: "**/tests/playground/*.spec.ts", use: { baseURL: playgroundURL, viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: [{
    command: "bun run preview -- --outDir ../docs/book --base / --host 127.0.0.1 --port 8841 --strictPort",
    url: "http://127.0.0.1:8841",
    timeout: 15_000,
    reuseExistingServer: false,
  }, {
    command: "bun run preview -- --host 127.0.0.1 --port 8843 --strictPort",
    url: playgroundURL,
    timeout: 15_000,
    reuseExistingServer: false,
  }],
});
