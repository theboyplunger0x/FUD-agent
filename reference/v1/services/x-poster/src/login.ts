import { chromium } from "playwright-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import readline from "node:readline";

chromium.use(StealthPlugin());

const __dirname  = dirname(fileURLToPath(import.meta.url));
const STATE_PATH = resolve(__dirname, "..", "data", "x-state.json");

function waitForEnter(prompt: string): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, () => {
      rl.close();
      resolve();
    });
  });
}

async function main(): Promise<void> {
  console.log("[x-login] Launching Chromium (headed) with stealth...");
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    locale:   "en-US",
  });
  const page = await context.newPage();

  console.log("[x-login] Opening x.com login flow...");
  await page.goto("https://x.com/i/flow/login", { waitUntil: "domcontentloaded" });

  console.log("");
  console.log("================================================================");
  console.log("  Log in manually with your @FUDmarkets credentials.");
  console.log("  Complete 2FA / captcha if prompted.");
  console.log("  Wait until you see the home feed.");
  console.log("  Then come back here and press ENTER.");
  console.log("================================================================");
  console.log("");

  await waitForEnter("Press ENTER when login is complete > ");

  const finalUrl = page.url();
  if (!/x\.com\/(home|FUDmarkets|i\/)/i.test(finalUrl)) {
    console.warn(`[x-login] WARNING: current URL is ${finalUrl} — expected /home. Saving state anyway.`);
  } else {
    console.log(`[x-login] OK — current URL: ${finalUrl}`);
  }

  await mkdir(dirname(STATE_PATH), { recursive: true });
  await context.storageState({ path: STATE_PATH });
  console.log(`[x-login] Storage state saved to ${STATE_PATH}`);
  console.log("[x-login] Done. Closing browser.");

  await browser.close();
}

main().catch((e) => {
  console.error("[x-login] Failed:", e);
  process.exit(1);
});
