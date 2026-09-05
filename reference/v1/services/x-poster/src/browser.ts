import { chromium } from "playwright-extra";
import type { Browser, BrowserContext, Page } from "playwright";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { existsSync } from "node:fs";

chromium.use(StealthPlugin());

export interface PostReplyResult {
  ok:           boolean;
  newTweetId?:  string;
  url?:         string;
  error?:       string;
  screenshot?:  string;
}

export interface PostReplyOptions {
  statePath:  string;
  replyToId:  string;
  text:       string;
  /** When true, run with visible browser (debugging). Defaults to true in dev, false in prod. */
  headed?:    boolean;
}

function rand(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Post a reply on X via Playwright UI automation, using a saved storage state.
 *
 * Returns a structured result instead of throwing for predictable callers.
 * Browser is launched fresh per call — at low volume (single-digit replies/day)
 * the ~3s startup is negligible and isolates failures.
 */
export async function postReplyViaSession(opts: PostReplyOptions): Promise<PostReplyResult> {
  if (!existsSync(opts.statePath)) {
    return { ok: false, error: `state_not_found:${opts.statePath}` };
  }
  if (!/^\d{15,20}$/.test(opts.replyToId)) {
    return { ok: false, error: `invalid_reply_to_id:${opts.replyToId}` };
  }
  if (!opts.text || opts.text.trim().length === 0) {
    return { ok: false, error: "empty_text" };
  }

  const headed = opts.headed ?? false;
  let browser:  Browser | null = null;
  let context:  BrowserContext | null = null;
  let page:     Page | null = null;

  try {
    browser = await chromium.launch({ headless: !headed });
    context = await browser.newContext({
      storageState: opts.statePath,
      viewport:     { width: 1280, height: 800 },
      locale:       "en-US",
    });
    page = await context.newPage();

    const directUrl = `https://x.com/i/web/status/${opts.replyToId}`;
    await page.goto(directUrl, { waitUntil: "domcontentloaded" });
    await sleep(rand(2500, 4000));

    if (/\/(login|i\/flow\/login)/.test(page.url())) {
      return { ok: false, error: "session_expired" };
    }

    const textarea = page.locator('[data-testid="tweetTextarea_0"]').first();

    // Sometimes textarea is collapsed; click placeholder to expand.
    const visible = await textarea.isVisible().catch(() => false);
    if (!visible) {
      const placeholder = page
        .locator('[data-testid="tweetTextarea_0_RichTextInputContainer"], [aria-label*="reply" i]')
        .first();
      await placeholder.click({ timeout: 5_000 }).catch(() => null);
      await sleep(rand(800, 1400));
    }

    try {
      await textarea.waitFor({ state: "visible", timeout: 10_000 });
    } catch {
      return { ok: false, error: "textarea_not_found" };
    }

    await textarea.click();
    await sleep(rand(400, 900));

    await page.keyboard.type(opts.text, { delay: rand(35, 80) });
    await sleep(rand(700, 1300));

    const replyButton = page
      .locator('[data-testid="tweetButtonInline"], [data-testid="tweetButton"]')
      .first();
    try {
      await replyButton.waitFor({ state: "visible", timeout: 5_000 });
    } catch {
      return { ok: false, error: "post_button_not_found" };
    }
    await sleep(rand(300, 700));
    await replyButton.click();

    // Success signal: contenteditable textarea is cleared after a successful post.
    let posted = false;
    for (let i = 0; i < 24; i++) {
      await sleep(500);
      const content = await textarea.textContent().catch(() => null);
      if (content !== null && content.trim() === "") {
        posted = true;
        break;
      }
    }

    if (!posted) {
      return { ok: false, error: "post_not_confirmed" };
    }

    // Try to find the new tweet ID by navigating to the user's profile or
    // looking at the conversation thread. Best-effort — may return undefined.
    // X doesn't surface the new tweet ID in the URL after an inline reply,
    // so for now we report success without the ID. The caller can poll the
    // user's recent tweets to find it.
    return { ok: true };
  } catch (e: any) {
    const msg = String(e?.message ?? e).slice(0, 400);
    return { ok: false, error: `playwright_error:${msg}` };
  } finally {
    try { await context?.close(); } catch {}
    try { await browser?.close(); } catch {}
  }
}
