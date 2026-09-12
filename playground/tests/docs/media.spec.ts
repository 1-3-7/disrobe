import { readFile } from "node:fs/promises";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function waitForPosters(page: Page): Promise<void> {
  await page.locator("video").evaluateAll(async (videos: HTMLVideoElement[]): Promise<void> => {
    await Promise.all(videos.map(async (video: HTMLVideoElement): Promise<void> => {
      const poster: HTMLImageElement = new Image();
      poster.src = video.poster;
      await poster.decode();
      if (poster.naturalWidth === 0 || poster.naturalHeight === 0) {
        throw new Error(`Video poster did not decode: ${video.poster}`);
      }
    }));
    await new Promise<void>((resolve): void => {
      requestAnimationFrame((): void => {
        requestAnimationFrame((): void => {
          resolve();
        });
      });
    });
  });
}

test("walkthrough and teaser decode, play and expose their captions", async ({ page }): Promise<void> => {
  const errors: string[] = [];
  page.on("pageerror", (error: Error): void => { errors.push(error.message); });
  page.on("console", (message): void => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("response", (response): void => {
    if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
  });
  await page.goto("/assets/walkthrough/watch.html");
  for (const [id, captions] of [["walkthrough", 6], ["teaser", 4]] as const) {
    const player = page.locator(`video#${id}`);
    await player.evaluate(async (video: HTMLVideoElement): Promise<void> => { video.muted = true; await video.play(); });
    await expect.poll(async (): Promise<number> => player.evaluate((video: HTMLVideoElement): number => video.readyState)).toBeGreaterThanOrEqual(2);
    const duration: number = await player.evaluate((video: HTMLVideoElement): number => video.duration);
    expect(duration).toBeCloseTo(id === "walkthrough" ? 36 : 20, 1);
    expect(await player.evaluate((video: HTMLVideoElement): number => video.videoWidth)).toBe(1920);
    expect(await player.evaluate((video: HTMLVideoElement): number => video.videoHeight)).toBe(1080);
    await expect.poll(async (): Promise<number> => player.evaluate((video: HTMLVideoElement): number => video.textTracks[0]?.cues?.length ?? 0)).toBe(captions);
    await expect.poll(async (): Promise<number> => player.evaluate((video: HTMLVideoElement): number => video.currentTime)).toBeGreaterThan(0.25);
    expect(await player.evaluate((video: HTMLVideoElement): number => video.getVideoPlaybackQuality().totalVideoFrames)).toBeGreaterThan(0);
    await player.evaluate((video: HTMLVideoElement): void => { video.pause(); video.currentTime = video.duration - 1; });
    await expect.poll(async (): Promise<boolean> => player.evaluate((video: HTMLVideoElement): boolean => !video.seeking && video.readyState >= 2)).toBe(true);
    expect(await player.evaluate((video: HTMLVideoElement): MediaError | null => video.error)).toBeNull();
  }
  expect(errors).toEqual([]);
});

test("media page has neutral themes, accessible controls and reachable source files", async ({ page }): Promise<void> => {
  const mediaRequests: string[] = [];
  page.on("request", (request): void => {
    if (new URL(request.url()).pathname.endsWith(".mp4")) mediaRequests.push(request.url());
  });
  await page.goto("/assets/walkthrough/watch.html");
  await waitForPosters(page);
  for (const [theme, background] of [["dark", "rgb(16, 16, 16)"], ["light", "rgb(250, 250, 250)"]] as const) {
    if (theme === "light") await page.getByRole("button", { name: "Light mode", exact: true }).click();
    await expect(page.locator("body")).toHaveCSS("background-color", background);
    expect(await page.evaluate((): boolean => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
    expect(result.violations).toEqual([]);
    await test.info().attach(`media-${theme}`, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  }
  expect(mediaRequests).toEqual([]);
  const transcript = await page.request.get("/assets/walkthrough/transcript.txt");
  expect(transcript.ok()).toBe(true);
  expect(await transcript.text()).toBe(await readFile(new URL("../../../docs/src/assets/walkthrough/transcript.txt", import.meta.url), "utf8"));
  await expect(page.getByRole("link", { name: "Read the transcript", exact: true })).toHaveAttribute("href", "transcript.txt");
});

test("introduction plays the complete walkthrough without looping", async ({ page }): Promise<void> => {
  const rangedMedia = await page.request.get("/assets/walkthrough/walkthrough.mp4", { headers: { Range: "bytes=524288-" } });
  expect(rangedMedia.status()).toBe(206);
  expect(rangedMedia.headers()["accept-ranges"]).toBe("bytes");
  expect(rangedMedia.headers()["content-range"]).toMatch(/^bytes 524288-\d+\/\d+$/);
  await page.goto("/introduction.html");
  const player = page.locator("video");
  await expect(player).toHaveCount(1);
  await expect(page.locator(".content h1")).toHaveText("disrobe: static software recovery");
  await expect(player).toHaveAttribute("controls", "");
  expect(await player.evaluate((video: HTMLVideoElement): boolean => video.loop)).toBe(false);
  await player.evaluate(async (video: HTMLVideoElement): Promise<void> => { video.muted = true; await video.play(); });
  await expect.poll(() => player.evaluate((video: HTMLVideoElement): number => video.currentTime), { timeout: 12_000 }).toBeGreaterThan(5);
  expect(await player.evaluate((video: HTMLVideoElement): number => video.duration)).toBeCloseTo(36, 1);
  await expect.poll(() => player.evaluate((video: HTMLVideoElement): number => video.textTracks[0]?.cues?.length ?? 0)).toBe(6);
  await player.evaluate((video: HTMLVideoElement): void => { video.pause(); video.currentTime = video.duration - 0.5; });
  await expect.poll(() => player.evaluate((video: HTMLVideoElement): boolean => !video.seeking && video.readyState >= 2)).toBe(true);
  await player.evaluate(async (video: HTMLVideoElement): Promise<void> => { await video.play(); });
  await expect.poll(() => player.evaluate((video: HTMLVideoElement): boolean => video.ended)).toBe(true);
  expect(await player.evaluate((video: HTMLVideoElement): MediaError | null => video.error)).toBeNull();
});
