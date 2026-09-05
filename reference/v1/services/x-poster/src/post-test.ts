import { chromium } from "playwright-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

chromium.use(StealthPlugin());

const __dirname  = dirname(fileURLToPath(import.meta.url));
const STATE_PATH = resolve(__dirname, "..", "data", "x-state.json");

function rand(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min));
}

async function main(): Promise<void> {
  const tweetUrl  = process.argv[2];
  const replyText = process.argv.slice(3).join(" ");
  if (!tweetUrl || !replyText) {
    console.error("Usage: npm run x:post-test \"<tweet URL>\" \"<reply text>\"");
    process.exit(1);
  }
  if (!existsSync(STATE_PATH)) {
    console.error(`[x-post-test] State file not found: ${STATE_PATH}`);
    console.error(`Run "npm run x:login" first.`);
    process.exit(1);
  }

  const idMatch = tweetUrl.match(/(\d{15,20})/);
  if (!idMatch) {
    console.error("[x-post-test] Could not extract tweet ID from URL.");
    process.exit(1);
  }
  const tweetId = idMatch[1];

  console.log("[x-post-test] Launching Chromium (headed) with saved state...");
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    storageState: STATE_PATH,
    viewport:     { width: 1280, height: 800 },
    locale:       "en-US",
  });
  const page = await context.newPage();

  const directUrl = `https://x.com/i/web/status/${tweetId}`;
  console.log(`[x-post-test] Navigating to ${directUrl}`);
  await page.goto(directUrl, { waitUntil: "domcontentloaded" });

  // Wait for the page to actually render (X is heavy SPA)
  await page.waitForTimeout(rand(2500, 4000));

  if (/\/(login|i\/flow\/login)/.test(page.url())) {
    console.error("[x-post-test] Got redirected to login. Session expired — re-run x:login.");
    await browser.close();
    process.exit(1);
  }

  // The reply textarea on X has a stable testid: tweetTextarea_0
  // Sometimes it's collapsed and we need to click a "Post your reply" placeholder first.
  console.log("[x-post-test] Looking for reply textarea (tweetTextarea_0)...");
  const textarea = page.locator('[data-testid="tweetTextarea_0"]').first();

  const isVisible = await textarea.isVisible().catch(() => false);
  if (!isVisible) {
    console.log("[x-post-test] Textarea not visible — trying placeholder click first...");
    // Try clicking the "Post your reply" placeholder/prompt
    const placeholder = page
      .locator('[data-testid="tweetTextarea_0_RichTextInputContainer"], [aria-label*="reply" i], div:has-text("Post your reply")')
      .first();
    try {
      await placeholder.click({ timeout: 5_000 });
      await page.waitForTimeout(rand(800, 1400));
    } catch (e) {
      console.warn("[x-post-test] Placeholder click failed:", (e as Error).message);
    }
  }

  try {
    await textarea.waitFor({ state: "visible", timeout: 10_000 });
  } catch (e) {
    const screenshotPath = resolve(__dirname, "..", "data", `error-${Date.now()}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });
    console.error(`[x-post-test] Could not find reply textarea. Screenshot: ${screenshotPath}`);
    console.error(`[x-post-test] Current URL: ${page.url()}`);
    console.error(`[x-post-test] Page title: ${await page.title()}`);
    await browser.close();
    process.exit(1);
  }

  console.log("[x-post-test] Clicking textarea...");
  await textarea.click();
  await page.waitForTimeout(rand(400, 900));

  console.log(`[x-post-test] Typing reply (${replyText.length} chars)...`);
  await page.keyboard.type(replyText, { delay: rand(35, 80) });
  await page.waitForTimeout(rand(700, 1300));

  console.log("[x-post-test] Locating Reply/Post button...");
  const replyButton = page
    .locator('[data-testid="tweetButtonInline"], [data-testid="tweetButton"]')
    .first();
  try {
    await replyButton.waitFor({ state: "visible", timeout: 5_000 });
  } catch {
    const screenshotPath = resolve(__dirname, "..", "data", `error-${Date.now()}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });
    console.error(`[x-post-test] Could not find post button. Screenshot: ${screenshotPath}`);
    await browser.close();
    process.exit(1);
  }
  await page.waitForTimeout(rand(300, 700));

  console.log("[x-post-test] Clicking Reply button...");
  await replyButton.click();

  // Better success signal: after a successful post, the contenteditable textarea
  // is cleared (inner text becomes empty / placeholder reappears). The textarea
  // itself often stays visible (X reuses it for the next reply).
  console.log("[x-post-test] Waiting for textarea to clear (post confirmation)...");
  let posted = false;
  for (let i = 0; i < 20; i++) {
    await page.waitForTimeout(500);
    const content = await textarea.textContent().catch(() => null);
    if (content !== null && content.trim() === "") {
      posted = true;
      break;
    }
  }
  if (posted) {
    console.log("[x-post-test] OK — textarea cleared. Reply posted successfully.");
  } else {
    const screenshotPath = resolve(__dirname, "..", "data", `error-${Date.now()}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });
    const remaining = await textarea.textContent().catch(() => "(read failed)");
    console.warn(`[x-post-test] WARN — textarea still has content after 10s: "${remaining}". Screenshot: ${screenshotPath}`);
  }

  console.log("[x-post-test] Keeping browser open 5s so you can see the result...");
  await page.waitForTimeout(5_000);
  await browser.close();
}

main().catch((e) => {
  console.error("[x-post-test] Failed:", e);
  process.exit(1);
});
