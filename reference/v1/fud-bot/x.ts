import Anthropic from "@anthropic-ai/sdk";
import { db } from "../db/client.js";
import { createHmac, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { checkMarketCreationRateLimit, recordMarketCreation, resolveTokenMetaFromCA, isTokenBanned } from "./botGuards.js";
import { resolveSafeDisplayTicker } from "../services/tokenIdentity.js";
import { tryAutosignLazyMarket, checkAutosignGate } from "../services/autosignService.js";
import type { Timeframe } from "../lib/market.js";

const TWITTERAPI_KEY      = process.env.TWITTERAPI_KEY!;
const API                 = process.env.BACKEND_URL || "http://localhost:3001";
const FUDMARKETS_USERNAME = "FUDmarkets";
const TW_USERNAME         = process.env.X_TWITTER_USERNAME || FUDMARKETS_USERNAME;
const TW_PASSWORD         = process.env.X_TWITTER_PASSWORD!;
const TW_EMAIL            = process.env.X_TWITTER_EMAIL!;
const TW_PROXY            = process.env.X_PROXY_URL;
const TW_TOTP_SECRET      = process.env.X_TWITTER_TOTP_SECRET;
// Bot posting uses a SEPARATE X app from the OAuth user flow. The
// OAuth app (X_API_KEY/X_API_SECRET in routes/auth.ts) is set to
// "Read" so end users see a clean permission screen at Connect X.
// The bot app keeps "Read and Write" so it can post replies as
// @FUDmarkets. Fallback to X_* for local dev / staging where a
// single app may be used.
const X_API_KEY           = process.env.X_BOT_API_KEY           ?? process.env.X_API_KEY!;
const X_API_SECRET        = process.env.X_BOT_API_SECRET        ?? process.env.X_API_SECRET!;
const X_ACCESS_TOKEN      = process.env.X_BOT_ACCESS_TOKEN      ?? process.env.X_ACCESS_TOKEN!;
const X_ACCESS_TOKEN_SECRET = process.env.X_BOT_ACCESS_TOKEN_SECRET ?? process.env.X_ACCESS_TOKEN_SECRET!;


// USDC decimals for amount conversion

// Support up to 2 admin Telegram chat IDs
const ADMIN_TG_IDS: string[] = [
  process.env.ADMIN_TG_ID,
  process.env.ADMIN_TG_ID_2,
].filter(Boolean) as string[];

const anthropic = new Anthropic();

// ─── twitterapi.io cookie-based posting ──────────────────────────────────────

// AES-256-GCM encryption for X session cookies stored in bot_kv.
// BOT_COOKIE_ENCRYPTION_KEY must be a 64-char hex string (32 bytes).
// Without it, cookies are stored as plain text (backward compat warning only).
const _cookieEncKey = process.env.BOT_COOKIE_ENCRYPTION_KEY ?? "";
if (!_cookieEncKey) {
  console.warn("[x-agent] BOT_COOKIE_ENCRYPTION_KEY not set — X cookies stored unencrypted in DB");
} else if (Buffer.from(_cookieEncKey, "hex").length !== 32) {
  throw new Error("[x-agent] BOT_COOKIE_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)");
}

function encryptCookie(plain: string): string {
  if (!_cookieEncKey) return plain;
  const key = Buffer.from(_cookieEncKey, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
}

function decryptCookie(stored: string): string {
  if (!stored.startsWith("enc:")) return stored; // plain text (legacy or no key)
  if (!_cookieEncKey) throw new Error("[x-agent] BOT_COOKIE_ENCRYPTION_KEY required to decrypt stored cookie");
  const parts = stored.split(":");
  if (parts.length !== 4) throw new Error("[x-agent] Malformed encrypted cookie");
  const [, ivHex, tagHex, encHex] = parts;
  const key = Buffer.from(_cookieEncKey, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return decipher.update(Buffer.from(encHex, "hex")).toString("utf8") + decipher.final("utf8");
}

let cachedCookies: string | null = null;

async function loadCookies(): Promise<string | null> {
  if (cachedCookies) return cachedCookies;
  try {
    const { rows } = await db.query(`SELECT value FROM bot_kv WHERE key = 'x_login_cookies'`);
    if (rows[0]) { cachedCookies = decryptCookie(rows[0].value); return cachedCookies; }
  } catch (e: any) { console.error("[x-agent]", e.message ?? e); }
  return null;
}

async function saveCookies(cookies: string) {
  cachedCookies = cookies;
  await db.query(
    `INSERT INTO bot_kv (key, value) VALUES ('x_login_cookies', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [encryptCookie(cookies)]
  );
}

async function twitterLogin(retries = 5): Promise<string | null> {
  console.log("[x-agent] Logging in to Twitter via twitterapi.io...");
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch("https://api.twitterapi.io/twitter/user_login_v2", {
        method:  "POST",
        headers: { "X-API-Key": TWITTERAPI_KEY, "Content-Type": "application/json" },
        body:    JSON.stringify({ user_name: TW_USERNAME, password: TW_PASSWORD, email: TW_EMAIL, ...(TW_PROXY ? { proxy: TW_PROXY } : {}), ...(TW_TOTP_SECRET ? { totp_secret: TW_TOTP_SECRET } : {}) }),
      });
      const data = await res.json() as any;
      if (res.status === 429) {
        console.warn(`[x-agent] Login 429 — retrying in 6s (attempt ${i + 1}/${retries})`);
        await new Promise(r => setTimeout(r, 6000));
        continue;
      }
      if (!res.ok || !data.login_cookies) {
        console.error(`[x-agent] Login failed: ${JSON.stringify(data)}`);
        return null;
      }
      console.log("[x-agent] Twitter login successful — cookies saved");
      await saveCookies(data.login_cookies);
      return data.login_cookies;
    } catch (e: any) {
      console.error(`[x-agent] Login error: ${e.message}`);
      return null;
    }
  }
  console.error("[x-agent] Login failed after retries");
  return null;
}

function buildOAuthHeader(method: string, url: string): string {
  const nonce     = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const oauthParams: Record<string, string> = {
    oauth_consumer_key:     X_API_KEY,
    oauth_nonce:            nonce,
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp:        timestamp,
    oauth_token:            X_ACCESS_TOKEN,
    oauth_version:          "1.0",
  };
  const sortedParams = Object.keys(oauthParams).sort()
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(oauthParams[k])}`)
    .join("&");
  const base      = `${method}&${encodeURIComponent(url)}&${encodeURIComponent(sortedParams)}`;
  const signingKey = `${encodeURIComponent(X_API_SECRET)}&${encodeURIComponent(X_ACCESS_TOKEN_SECRET)}`;
  const signature  = createHmac("sha1", signingKey).update(base).digest("base64");
  oauthParams.oauth_signature = signature;
  return "OAuth " + Object.keys(oauthParams).sort()
    .map(k => `${encodeURIComponent(k)}="${encodeURIComponent(oauthParams[k])}"`)
    .join(", ");
}

// ─── Media upload (Twitter API v1.1, OAuth 1.0a multipart) ────────────────
// X flags bot accounts that post bare links as low-quality / spam. Attaching
// an image to every reply makes the tweet look like a normal user post, not
// a spam relay. Logo bytes are fetched once from the FE host
// (https://fud.markets/og/fud-bot-card.png) and cached in memory; media_ids
// expire after ~24h on Twitter's side so we re-upload when expired or on
// upload error. 2026-05-18 quick fix for spam flags.

const BOT_MEDIA_URL = process.env.BOT_REPLY_MEDIA_URL
  || `${process.env.FRONTEND_URL || "https://fud.markets"}/og/fud-bot-card.png`;

interface CachedMedia { id: string; expiresAt: number; }
let cachedMedia: CachedMedia | null = null;
let cachedImageBuf: Buffer | null = null;

async function fetchLogoBytes(): Promise<Buffer | null> {
  if (cachedImageBuf) return cachedImageBuf;
  try {
    const res = await fetch(BOT_MEDIA_URL);
    if (!res.ok) {
      console.warn(`[x-agent] logo fetch failed ${res.status} from ${BOT_MEDIA_URL}`);
      return null;
    }
    const arr = await res.arrayBuffer();
    cachedImageBuf = Buffer.from(arr);
    return cachedImageBuf;
  } catch (e: any) {
    console.warn(`[x-agent] logo fetch error: ${e?.message ?? e}`);
    return null;
  }
}

async function uploadMediaToTwitter(buf: Buffer): Promise<string | null> {
  const url = "https://upload.twitter.com/1.1/media/upload.json";
  // OAuth header signs the URL+method; multipart body is NOT included in
  // the OAuth signature (Twitter spec for media/upload). buildOAuthHeader
  // already handles that path because it doesn't sign body params.
  try {
    const form = new FormData();
    form.append("media", new Blob([new Uint8Array(buf)]), "fud-card.png");
    const res = await fetch(url, {
      method: "POST",
      headers: { "Authorization": buildOAuthHeader("POST", url) },
      body: form as any,
    });
    const data = await res.json() as any;
    if (!res.ok || !data?.media_id_string) {
      console.warn(`[x-agent] media upload failed ${res.status}: ${JSON.stringify(data).slice(0, 200)}`);
      return null;
    }
    console.log(`[x-agent] media uploaded id=${data.media_id_string} size=${buf.length}b`);
    return data.media_id_string as string;
  } catch (e: any) {
    console.warn(`[x-agent] media upload error: ${e?.message ?? e}`);
    return null;
  }
}

/** Get a cached or fresh Twitter media_id for the FUD bot card. Returns
 *  null if upload failed — caller should still post without media. */
async function getBotCardMediaId(): Promise<string | null> {
  if (cachedMedia && cachedMedia.expiresAt > Date.now()) return cachedMedia.id;
  const buf = await fetchLogoBytes();
  if (!buf) return null;
  const id = await uploadMediaToTwitter(buf);
  if (!id) return null;
  // Twitter docs: media_ids valid for ~24h. Refresh proactively at 20h.
  cachedMedia = { id, expiresAt: Date.now() + 20 * 60 * 60 * 1000 };
  return id;
}

/** Force a re-upload on next call. Used when Twitter returns "media not
 *  found" for an expired or invalidated media_id. */
function invalidateMediaCache(): void {
  cachedMedia = null;
}

export async function postReply(text: string, replyToId: string, opts?: { attachMedia?: boolean }): Promise<{ status: number; data: any }> {
  const url  = "https://api.twitter.com/2/tweets";
  const attach = opts?.attachMedia ?? true; // default ON for spam-resistance
  const body: any = { text };
  if (replyToId) body.reply = { in_reply_to_tweet_id: replyToId };

  if (attach) {
    const mediaId = await getBotCardMediaId();
    if (mediaId) body.media = { media_ids: [mediaId] };
  }

  console.log(`[x-agent] POST /2/tweets replyToId=${replyToId} text="${text.slice(0, 100)}" mediaAttached=${!!body.media}`);
  const res  = await fetch(url, {
    method:  "POST",
    headers: { "Authorization": buildOAuthHeader("POST", url), "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  const data = await res.json() as any;
  console.log(`[x-agent] POST /2/tweets status=${res.status} response=${JSON.stringify(data).slice(0, 300)}`);
  // Twitter sometimes 400s with "media_ids parameter is invalid" when the
  // cached id expired between upload and tweet. Invalidate + retry once
  // without media so the tweet still ships.
  if (!res.ok && body.media && /media[_-]?id/i.test(JSON.stringify(data))) {
    invalidateMediaCache();
    console.warn(`[x-agent] media_id rejected, retrying without media`);
    return postReply(text, replyToId, { attachMedia: false });
  }
  if (!res.ok) throw new Error(JSON.stringify(data));
  return { status: res.status, data };
}

// ─── x-poster bypass (Playwright UI automation behind shared HTTP service) ────
//
// Used for proactive replies (KOLs that haven't mentioned/quoted us). The
// official API blocks those at runtime with 403 — see project memory
// `project_x_api_reply_block.md`. The x-poster service drives a logged-in
// session via Playwright; coordinates in `project_x_poster_service.md`.

// Whitelist of error codes safe to surface back to operator chats.
// Anything else is masked as "internal_error" — playwright/state/url leaks
// sit in this masked set (paths, hostnames, stack traces).
const SAFE_X_POSTER_ERRORS = new Set<string>([
  "session_expired",
  "textarea_not_found",
  "post_button_not_found",
  "post_not_confirmed",
  "empty_text",
  "text_too_long",
  "invalid_reply_to_id",
  "idempotency_key_too_long",
  "busy_retry_later",
  "rate_limited",
  "shutting_down",
  "x_poster_not_configured",
  "write_failed",
  "unauthorized",
]);

function sanitizeXPosterError(raw: string | undefined): string {
  if (!raw) return "unknown";
  const head = raw.split(":")[0];
  return SAFE_X_POSTER_ERRORS.has(head) ? head : "internal_error";
}

export async function postViaSession(
  text:        string,
  replyToId:   string,
  idempotencyKey?: string,
): Promise<{ ok: boolean; status: number; error?: string }> {
  const baseUrl = process.env.X_POSTER_URL;
  const secret  = process.env.X_POSTER_SECRET;
  if (!baseUrl || !secret) {
    return { ok: false, status: 0, error: "x_poster_not_configured" };
  }
  const key = idempotencyKey ?? `${replyToId}:${Date.now()}`;
  try {
    console.log(`[x-agent] POST x-poster/reply replyToId=${replyToId} text="${text.slice(0, 100)}"`);
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/reply`, {
      method:  "POST",
      headers: {
        "Authorization": `Bearer ${secret}`,
        "Content-Type":  "application/json",
      },
      body: JSON.stringify({ replyToId, text, idempotencyKey: key }),
    });
    const data = await res.json().catch(() => null) as any;
    console.log(`[x-agent] x-poster/reply status=${res.status} ok=${data?.ok}`);
    if (!res.ok || data?.ok !== true) {
      return { ok: false, status: res.status, error: sanitizeXPosterError(data?.error) };
    }
    return { ok: true, status: res.status };
  } catch (e: any) {
    // fetch errors include the destination URL/hostname — never echo raw.
    console.error(`[x-agent] x-poster/reply request_failed: ${String(e?.message ?? e).slice(0, 200)}`);
    return { ok: false, status: 0, error: "internal_error" };
  }
}

// ─── twitterapi.io v3 (server-side session, no cookie needed for posting) ────

let v3LoginDone = false;

async function loginV3(): Promise<boolean> {
  console.log("[x-agent] Initiating v3 login...");
  try {
    const res = await fetch("https://api.twitterapi.io/twitter/user_login_v3", {
      method:  "POST",
      headers: { "X-API-Key": TWITTERAPI_KEY, "Content-Type": "application/json" },
      body:    JSON.stringify({
        user_name: TW_USERNAME,
        email:     TW_EMAIL,
        password:  TW_PASSWORD,
        proxy:     TW_PROXY,
      }),
    });
    const data = await res.json() as any;
    console.log(`[x-agent] v3 login init: ${JSON.stringify(data).slice(0, 200)}`);
    if (!res.ok || data.status !== "success") return false;

    // Poll until Active (max 60s)
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const poll = await fetch(`https://api.twitterapi.io/twitter/get_my_x_account_detail_v3?user_name=${TW_USERNAME}`, {
        headers: { "X-API-Key": TWITTERAPI_KEY },
      });
      const pd = await poll.json() as any;
      console.log(`[x-agent] v3 poll ${i + 1}: status=${pd.data?.status}`);
      if (pd.data?.status === "Active") {
        console.log("[x-agent] v3 session active");
        v3LoginDone = true;
        return true;
      }
    }
    console.error("[x-agent] v3 login timed out");
    return false;
  } catch (e: any) {
    console.error("[x-agent] v3 login error:", e.message);
    return false;
  }
}

async function postV3(text: string): Promise<void> {
  if (!v3LoginDone) {
    const ok = await loginV3();
    if (!ok) throw new Error("v3 login failed");
  }
  console.log(`[x-agent] send_tweet_v3 text="${text.slice(0, 100)}"`);
  const res = await fetch("https://api.twitterapi.io/twitter/send_tweet_v3", {
    method:  "POST",
    headers: { "X-API-Key": TWITTERAPI_KEY, "Content-Type": "application/json" },
    body:    JSON.stringify({ user_name: TW_USERNAME, text }),
  });
  const data = await res.json() as any;
  console.log(`[x-agent] send_tweet_v3 status=${res.status} response=${JSON.stringify(data).slice(0, 300)}`);
  if (!res.ok || data.status !== "success") throw new Error(JSON.stringify(data));
}

// Pending approvals: callbackId → { tweetId, xUsername, replies, timeout, msgIds, postingMode }
// postingMode is the dispatch hint:
//   "official" (default) → postReply via OAuth1 v2 (mentions flow, X allows when summoned)
//   "session"            → postViaSession via x-poster (proactive flow, bypass for KOL replies)
type PendingEntry = {
  tweetId:      string;
  xUsername:    string;
  replies:      string[];
  timeout:      ReturnType<typeof setTimeout>;
  msgIds:       Map<string, number>;
  postingMode?: "official" | "session";
};
const pending = new Map<string, PendingEntry>();

// Bounded growth — when a viral mention burst happens (many quotes/mentions
// + nobody approving), this prevents the Map from eating memory until the
// container is OOM-killed. Maps preserve insertion order, so we evict the
// oldest entry first (FIFO) and clear its timeout so we don't leak handles.
const PENDING_CAP = 200;
function setPending(key: string, entry: PendingEntry): void {
  if (pending.size >= PENDING_CAP) {
    const oldestKey = pending.keys().next().value as string | undefined;
    if (oldestKey) {
      const old = pending.get(oldestKey);
      if (old) {
        clearTimeout(old.timeout);
        // Best-effort edit the admin Telegram messages so admins don't stare
        // at a stale [Post]/[Reject] keyboard for an entry that was dropped.
        editAdminMessages(old.msgIds, `⚠️ *Evicted* (cap ${PENDING_CAP}) — @${old.xUsername}`)
          .catch(() => {});
      }
      pending.delete(oldestKey);
      console.warn(`[x-agent] pending cap (${PENDING_CAP}) reached — evicted ${oldestKey}`);
    }
  }
  pending.set(key, entry);
}

// Per-cycle caps — prevent burst of Anthropic / Telegram calls when many new
// mentions or quotes appear at once. Anything beyond the cap is left in the
// poll source (NOT marked processed) so the next cycle picks it up.
const MENTIONS_PER_CYCLE_CAP = 10;
const QUOTES_PER_CYCLE_CAP   = 10;

// Operational flags (default OFF for cost). Both ship dormant; flip when
// the bot is ready to take on reply-guy / quote-tracker work.
const X_QUOTES_ENABLED       = process.env.X_QUOTES_ENABLED === "1";
const X_REPLY_AGENT_ENABLED  = process.env.X_REPLY_AGENT_ENABLED === "1";
// Mention polling cadence. Old bot ran at 60s burning ~1/min idle. 5min is
// reactive enough for Twitter trades; bumps to 15min if cost is still high.
const MENTION_POLL_MS        = Math.max(60_000, Number(process.env.X_MENTION_POLL_MS) || 5 * 60_000);
const QUOTE_POLL_MS          = Math.max(60_000, Number(process.env.X_QUOTE_POLL_MS)   || 10 * 60_000);

// ─── Trade-intent parser ─────────────────────────────────────────────────────
// Three-state classifier so we don't burn Claude on tweets that aren't trying
// to open a market. Cheap regex — runs on every mention. Distinguishes:
//   - complete:        side + ticker + timeframe (ready to open)
//   - missing_timeframe: side + ticker but no tf (nudge to reply with tf)
//   - none:            no trade intent (only handled by reply-agent path)
// CA is THE identifier. Tickers are ambiguous (50 PEPEs) and even
// real ones with the same symbol live on different chains. Marcos
// 2026-05-12: "NO USAMOS MAS TICKER. hay mucho margen de error. solo
// ca". Backend resolves symbol from CA via Dexscreener.
export type TradeIntent =
  | { kind: "complete";          side: "long" | "short"; ca: string; amount?: number; timeframe: string }
  | { kind: "missing_ca";        side: "long" | "short"; amount?: number; timeframe?: string }
  | { kind: "missing_timeframe"; side: "long" | "short"; ca: string; amount?: number }
  | { kind: "none" };

// Match the timeframes the trading UI offers (15m / 1h / 24h / 1w).
// 1m and 5m are silenced (too short to be tradeable); 1w added.
// Marcos 2026-05-25.
const VALID_TIMEFRAMES = new Set(["15m", "1h", "24h", "1w"]);

export function parseTradeIntent(rawText: string): TradeIntent {
  const text = rawText.toLowerCase();

  // Side — verbs + arrows + emojis. Broadened to catch common variants
  // (going long/short, bullish/bearish, dump/moon/rugpull). Marcos
  // 2026-05-12: "ampliar varios parametros por las dudas".
  //
  // 2026-05-16: false-positive bot reply to @GNftarmy whose tweet
  // started with "Crypto takes have been free for too long." → "long"
  // matched \blong\b. Strip narrative uses of long/short BEFORE side
  // detection so they don't trigger any downstream classification.
  const narrativeLong  = /\b(for|too|so|as|how|this|that|all|not|isn'?t|wasn'?t)\s+long\b/g;
  const narrativeShort = /\b(in|fall(s|ing|en)?|come up|run|cut|stopped?|story)\s+short\b/g;
  const stripped = text
    .replace(narrativeLong, " ")
    .replace(narrativeShort, " ");

  let side: "long" | "short" | null = null;
  if (/\b(long(ing)?|buy(ing)?|bull(ish)?|moon(ing)?|pump(ing)?|ape|yolo)\b/.test(stripped) || /▲|🟢|🚀/.test(rawText)) side = "long";
  else if (/\b(short(ing)?|sell(ing)?|bear(ish)?|dump(ing)?|rug(pull)?|crash|fade|puts?|rekt)\b/.test(stripped) || /▼|🔴|📉|🩸/.test(rawText)) side = "short";

  // Trade-action verb — extra signal that user is trying to open a market.
  // Lets us distinguish "I went long on $X" (chitchat) from "open long on $X" (action).
  const hasOpenVerb = /\b(open|place|bet|wager|put|create|start)\b/.test(text);

  // Past-tense / completed-action markers. If present, the user is
  // describing something they ALREADY did, not asking the bot to act.
  // Examples that hit this: "just took a $X long", "I went long on $X
  // earlier", "I bought $X", "tested @FUDmarkets and shorted $Y".
  // Marcos 2026-05-13: false-positive reply to a positive mention by
  // @crypto_pranjal whose tweet was past tense.
  // "went"/"made"/"had" removed — too common in mixed intents ("went through
  // the analysis, going long", "made up my mind to short"). Keep only
  // unambiguous past-action markers or "just + verb" combos. Codex P2 2026-05-14.
  const hasPastTenseMarker = /\b(took|bought|sold|tested|tried|just\s+(?:bought|sold|went|took|opened|placed))\b/.test(text);

  // Ticker — leading $ followed by letter. Marcos 2026-05-12: do NOT
  // use as identifier (50 PEPE copycats out there). Kept as a soft
  // signal that the tweet is trying to trade something.
  const tickerHint = /\$[A-Za-z][A-Za-z0-9]{1,9}\b/.test(rawText);

  // Amount — broad: $50, 50$, "50 usdc", "50 usd", "$50.5", "50 bucks".
  const amountMatch = rawText.match(
    /(?:\$\s*(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*\$|(\d+(?:\.\d+)?)\s*(?:usdc|usd|bucks?|dollars?))\b/i,
  );

  // Contract address. EVM 0x… or Solana base58.
  const evmCa  = rawText.match(/\b(0x[a-fA-F0-9]{40})\b/);
  const solCa  = rawText.match(/\b([1-9A-HJ-NP-Za-km-z]{32,44})\b/);
  const ca = evmCa
    ? evmCa[1]
    : solCa && solCa[1].length >= 32 && !/^\$/.test(solCa[0])
      ? solCa[1]
      : null;

  const amount = amountMatch
    ? parseFloat(amountMatch[1] ?? amountMatch[2] ?? amountMatch[3])
    : undefined;

  // Trade-attempt detection. Multi-tier so we catch genuine intent
  // (even with errors / missing info) but reject chitchat:
  //
  // STRONG signals (any one → trade attempt):
  //   - side + CA (real address = real intent)
  //   - side + explicit open verb (open/place/bet/wager/put/create/start)
  //   - side + amount (someone naming a $ amount means they're trying)
  // WEAK signal (alone → not enough):
  //   - side + ticker only ($PEPE long) — ambiguous, often chitchat
  //
  // PAST-TENSE handling: past-tense markers ("took / bought / tested /
  // tried / just bought…") describe what the user did, not what they
  // want the bot to do. Reject UNLESS the tweet also carries a current-
  // intent marker — an imperative verb ("open"), a now/let's/going-to
  // phrase, or a CA — meaning a mixed message like "tested it earlier,
  // now open long $5 0x… 1h" has a real live intent in the second
  // clause. Codex Pass 9 P2: hard-reject was dropping valid mixed
  // intents on the floor.
  if (!side) return { kind: "none" };
  const hasCurrentIntentMarker = hasOpenVerb || !!ca || /\b(now|currently|going to|gonna|i'?ll|let'?s)\b/.test(text);
  if (hasPastTenseMarker && !hasCurrentIntentMarker) return { kind: "none" };
  const isStrongIntent = !!ca || hasOpenVerb || !!amount;
  if (!isStrongIntent) return { kind: "none" };

  // Timeframe — natural language ("15 min", "1 hour", "2 weeks") and
  // compact form ("15m", "1h", "1w"). Order matters: longest options first so
  // alternation doesn't short-circuit on "m" inside "minutes". Valid bins now
  // 15m / 1h / 24h / 1w (1m + 5m silenced). Marcos 2026-05-25.
  const tfMatch = text.match(/\b(\d+)\s*(weeks?|minutes?|mins?|hours?|hrs?|days?|w|m|h|d)\b/);
  let timeframe: string | undefined;
  if (tfMatch) {
    const num  = parseInt(tfMatch[1], 10);
    const unit = tfMatch[2];
    let normalized: string | undefined;
    if (/^w/.test(unit)) {
      normalized = "1w";
    } else if (/^(m|min)/.test(unit)) {
      // 5m silenced → 15m is the floor.
      if (num <= 30)      normalized = "15m";
      else                normalized = "1h";
    } else if (/^(h|hr|hour)/.test(unit)) {
      if (num <= 1)       normalized = "1h";
      else if (num <= 24) normalized = "24h";
      else                normalized = "1w";
    } else if (/^d/.test(unit)) {
      // a week or more → 1w, otherwise the 24h bin.
      normalized = num >= 7 ? "1w" : "24h";
    }
    if (normalized && VALID_TIMEFRAMES.has(normalized)) timeframe = normalized;
  }

  // Priority: CA first (can't trade without it), then timeframe.
  if (!ca) return { kind: "missing_ca", side, amount, timeframe };
  if (!timeframe) return { kind: "missing_timeframe", side, ca, amount };
  return { kind: "complete", side, ca, amount, timeframe };
}

// ─── Templated replies ───────────────────────────────────────────────────────
// These post directly via OAuth1 — no admin approval queue, no Claude calls.
// Used for trade-intent edge cases (missing tf, non-linked user).
//
// Anti-shadow-ban (Marcos 2026-05-21): X flagged the bot for repetitive
// identical replies (`Hey @user, sign up at fud.markets...`) → shadow ban.
// Two defenses below:
//   1. Per-(user, kind) throttle: 1 templated reply of each kind per X
//      handle every 7 days. Subsequent matches are silent. Lets brand-
//      new users see ONE explainer, returning users don't get spammed.
//   2. Paraphrase pool: each `kind` has N variants. Pick by stable hash
//      of (xUsername + kind) so the SAME user always sees the same
//      variant (no detectable rotation per user), different users see
//      different variants → no signature pattern X can flag.

/** Variant pools keyed by reply kind. ALL variants must convey the
 *  same actionable info. Keep under 270 chars. Include @user via the
 *  `__U__` placeholder so each variant reads naturally. */
const REPLY_VARIANTS: Record<string, string[]> = {
  signup: [
    `@__U__ trading from X needs a FUD account + Autosign. Set both up at fud.markets and try again.`,
    `@__U__ you need to enable Autosign first — sign up at fud.markets and you can trade straight from a tweet.`,
    `@__U__ no FUD account linked. Head to fud.markets, finish setup + flip Autosign on.`,
    `@__U__ link a FUD account at fud.markets and turn on Autosign — then mention me again and the trade goes through.`,
  ],
  no_autosign_consent: [
    `@__U__ your FUD account exists but Autosign isn't on. Toggle it in fud.markets settings.`,
    `@__U__ Autosign is off on your account — flip it on in fud.markets settings to trade from here.`,
    `@__U__ flip Autosign on in your fud.markets settings and re-mention me.`,
    `@__U__ Autosign needed before I can place this — settings on fud.markets, then mention me again.`,
  ],
  feature_disabled: [
    `@__U__ Autosign is paused for maintenance right now — try again in a few minutes.`,
    `@__U__ Autosign is temporarily off platform-wide. Give it a few minutes and try again.`,
    `@__U__ we paused Autosign briefly for a maintenance window — back in a few.`,
  ],
  wallet_incomplete: [
    `@__U__ your wallet setup isn't finished. Settings → Autosign on fud.markets to wrap it up.`,
    `@__U__ finish your wallet setup in fud.markets Settings → Autosign, then re-mention me.`,
    `@__U__ wallet setup pending — fud.markets Settings → Autosign and you're done.`,
  ],
};

/** Stable hash → variant index. Deterministic per (user, kind) so the
 *  same user always sees the same variant (no "obviously rotating
 *  template" signature for X spam detection). */
function pickVariant(xUsername: string, kind: string, pool: string[]): { idx: number; text: string } {
  if (pool.length === 0) return { idx: 0, text: "" };
  let h = 0;
  const seed = `${xUsername.toLowerCase()}::${kind}`;
  for (let i = 0; i < seed.length; i++) h = ((h << 5) - h + seed.charCodeAt(i)) | 0;
  const idx = Math.abs(h) % pool.length;
  return { idx, text: pool[idx].replace(/__U__/g, xUsername) };
}

const REPLY_COOLDOWN_DAYS = 7;

/** Has this (user, kind) been replied to within the cooldown window?
 *  Returns true to SKIP the reply silently. */
async function alreadyRepliedRecently(xUsername: string, kind: string): Promise<boolean> {
  try {
    // Codex P2 2026-05-21: prior version used $2 for both `kind` and the
    // interval cast, leaving the cooldown value ($3) unreferenced — the
    // cast became "<kind> days" which threw and the catch returned false
    // (cooldown silently disabled). Interval value now correctly bound to $3.
    const { rows: [r] } = await db.query<{ recent: boolean }>(
      `SELECT (replied_at > NOW() - ($3 || ' days')::INTERVAL) AS recent
         FROM x_bot_reply_log
        WHERE x_username = $1 AND kind = $2
        LIMIT 1`,
      [xUsername.toLowerCase(), kind, String(REPLY_COOLDOWN_DAYS)],
    );
    return !!r?.recent;
  } catch (e: any) {
    console.warn(`[x-agent] reply-log check failed:`, e?.message ?? e);
    return false;
  }
}

async function logTemplatedReply(xUsername: string, kind: string, variantIdx: number): Promise<void> {
  try {
    await db.query(
      `INSERT INTO x_bot_reply_log (x_username, kind, variant_idx, replied_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (x_username, kind) DO UPDATE
         SET variant_idx = EXCLUDED.variant_idx,
             replied_at  = NOW()`,
      [xUsername.toLowerCase(), kind, variantIdx],
    );
  } catch (e: any) {
    console.warn(`[x-agent] reply-log insert failed:`, e?.message ?? e);
  }
}

/** Post a templated reply with anti-shadow-ban guardrails. Caller
 *  passes a `kind` that matches REPLY_VARIANTS — fixed text overrides
 *  are still supported via the `text` arg for one-off non-throttled
 *  replies (missing_ca, missing_tf nudges that block trade intent and
 *  must always fire). */
async function postTemplatedReply(
  args:
    | { mode: "fixed"; text: string; tweetId: string; label: string }
    | { mode: "throttled"; xUsername: string; kind: keyof typeof REPLY_VARIANTS; tweetId: string },
): Promise<void> {
  if (args.mode === "throttled") {
    const { xUsername, kind, tweetId } = args;
    // Silent skip when same (user, kind) replied within cooldown.
    if (await alreadyRepliedRecently(xUsername, kind)) {
      console.log(`[x-agent] templated reply (${kind}) skipped — cooldown active for @${xUsername}`);
      return;
    }
    const pool = REPLY_VARIANTS[kind] ?? [];
    if (pool.length === 0) {
      console.warn(`[x-agent] no variant pool for kind=${kind}`);
      return;
    }
    const picked = pickVariant(xUsername, kind, pool);
    try {
      const r = await postReply(picked.text, tweetId);
      console.log(`[x-agent] templated reply (${kind}/v${picked.idx}) posted to @${xUsername}: status=${r.status}`);
      await logTemplatedReply(xUsername, kind, picked.idx);
    } catch (e: any) {
      console.error(`[x-agent] templated reply (${kind}) failed for @${xUsername}:`, e.message ?? e);
    }
    return;
  }
  // Fixed-text mode (legacy callers).
  try {
    const r = await postReply(args.text, args.tweetId);
    console.log(`[x-agent] templated reply (${args.label}) posted: status=${r.status}`);
  } catch (e: any) {
    console.error(`[x-agent] templated reply (${args.label}) failed:`, e.message ?? e);
  }
}

// Telegram-side backoff. When the Bot API returns 429, all in-flight admin
// notifications skip until this timestamp passes — avoids piling up retries
// against a rate-limited endpoint while polling keeps adding work.
let telegramBackoffUntil = 0;

let lastPollTime: number = Math.floor(Date.now() / 1000) - 300; // default: 5 min ago
const processedIds = new Set<string>(); // dedup within a session

async function loadLastPollTime() {
  try {
    const { rows } = await db.query(`SELECT value FROM bot_kv WHERE key = 'x_last_poll_time'`);
    if (rows[0]) { lastPollTime = parseInt(rows[0].value); console.log(`[x-agent] Loaded lastPollTime=${lastPollTime}`); }
  } catch (e: any) { console.error("[x-agent]", e.message ?? e); }
}

async function saveLastPollTime(t: number) {
  try {
    await db.query(
      `INSERT INTO bot_kv (key, value) VALUES ('x_last_poll_time', $1)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [t.toString()]
    );
  } catch (e: any) { console.error("[x-agent]", e.message ?? e); }
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

function mintToken(userId: string, username: string): string {
  const secret  = process.env.JWT_SECRET!;
  const header  = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ userId, username })).toString("base64url");
  const sig     = createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${sig}`;
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

async function getUserByXUsername(xUsername: string) {
  const { rows } = await db.query(
    `SELECT id, username, balance_usd FROM users WHERE x_username = $1`,
    [xUsername.toLowerCase()]
  );
  return rows[0] ?? null;
}

// ─── Cooldown: max 5 mentions per user per 10 minutes ────────────────────────

const cooldowns = new Map<string, number[]>(); // xUsername → timestamps

function checkCooldown(xUsername: string): boolean {
  const now    = Date.now();
  const window = 10 * 60 * 1000; // 10 minutes
  const limit  = 5;
  const times  = (cooldowns.get(xUsername) ?? []).filter(t => now - t < window);
  if (times.length >= limit) return false; // blocked
  cooldowns.set(xUsername, [...times, now]);
  return true;
}

// ─── Content filter: skip empty/emoji-only/too-short mentions ────────────────

function hasSubstance(text: string): boolean {
  // Strip @mentions, URLs, emojis, punctuation and check if anything real remains
  const stripped = text
    .replace(/@\w+/g, "")
    .replace(/https?:\/\/\S+/g, "")
    .replace(/[\u{1F000}-\u{1FFFF}]/gu, "")
    .replace(/[\u{2600}-\u{27BF}]/gu, "")
    .replace(/[^a-zA-Z0-9áéíóúñüÁÉÍÓÚÑÜ\s$]/g, "")
    .trim();
  // Need at least 1 real word
  const words = stripped.split(/\s+/).filter(w => w.length > 0);
  return words.length >= 1;
}

// ─── Filter: should we process this mention? ─────────────────────────────────

async function shouldProcess(tweet: any): Promise<{ ok: boolean; reason: string }> {
  const xUsername = (tweet.author?.userName ?? "").toLowerCase();
  const text      = (tweet.text ?? "").replace(/@FUDmarkets/gi, "").trim();

  // 1. Content filter — skip emoji-only / completely empty
  if (!hasSubstance(text)) return { ok: false, reason: `no substance (text="${text}")` };

  // 2. Cooldown — max 5 per user per 10 min
  if (!checkCooldown(xUsername)) return { ok: false, reason: "cooldown" };

  // 3. Everyone else passes — linked users, verified, and regular users all welcome
  return { ok: true, reason: "ok" };
}

// ─── Telegram notification ───────────────────────────────────────────────────

/** Send a message to all admin chats. Returns Map<chatId, messageId> for later editing. */
async function sendToAdminTelegram(text: string, inlineKeyboard?: object): Promise<Map<string, number>> {
  const msgIds = new Map<string, number>();
  if (!ADMIN_TG_IDS.length || !process.env.BOT_TOKEN) {
    console.warn("[x-agent] sendToAdminTelegram skipped — ADMIN_TG_IDS or BOT_TOKEN not set");
    return msgIds;
  }
  // Skip entirely if we're inside a Telegram-side backoff window.
  if (Date.now() < telegramBackoffUntil) {
    const left = Math.ceil((telegramBackoffUntil - Date.now()) / 1000);
    console.warn(`[x-agent] sendToAdminTelegram skipped — backoff active (${left}s left)`);
    return msgIds;
  }
  for (const chatId of ADMIN_TG_IDS) {
    const body: any = { chat_id: chatId, text, parse_mode: "Markdown" };
    if (inlineKeyboard) body.reply_markup = { inline_keyboard: inlineKeyboard };
    try {
      const res = await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json() as any;
        msgIds.set(chatId, data.result?.message_id);
      } else if (res.status === 429) {
        // Respect retry_after; pause ALL further admin sends for the duration.
        // NOTE: this skips remaining admins in this round AND silences the
        // backoff window globally. If admin #1 hit 429, admin #2 misses the
        // current draft AND any drafts until the backoff expires. Correct
        // tradeoff at high volume (we don't want to thrash a rate-limited API),
        // but admin #2 will see fewer notifications during a burst.
        const errBody    = await res.json().catch(() => ({} as any));
        const retryAfter = Number(errBody?.parameters?.retry_after ?? 5);
        telegramBackoffUntil = Date.now() + Math.max(1, retryAfter) * 1000;
        console.warn(`[x-agent] Telegram 429 — backoff for ${retryAfter}s`);
        break; // stop sending to remaining admins this round
      } else {
        const err = await res.text();
        console.error(`[x-agent] Telegram send to ${chatId} failed: ${res.status} ${err}`);
      }
    } catch (e: any) {
      console.error(`[x-agent] Telegram send to ${chatId} error: ${e.message}`);
    }
  }
  return msgIds;
}

/** Edit a previously sent message (removes buttons, shows status). */
async function editAdminMessages(msgIds: Map<string, number>, text: string) {
  if (!process.env.BOT_TOKEN) return;
  for (const [chatId, messageId] of msgIds) {
    try {
      await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/editMessageText`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ chat_id: chatId, message_id: messageId, text, parse_mode: "Markdown" }),
      });
    } catch (e: any) { console.error("[x-agent]", e.message ?? e); }
  }
}

// ─── Export helpers for Telegram bot ─────────────────────────────────────────

// Dispatch a confirmed reply to the right posting backend.
// "official" path = OAuth1 v2 (works for mentions where X allows reply).
// "session" path  = x-poster service (Playwright bypass for proactive replies).
async function dispatchApprovedPost(
  reply:      string,
  tweetId:    string,
  mode:       "official" | "session" = "official",
): Promise<void> {
  if (mode === "session") {
    const result = await postViaSession(reply, tweetId);
    if (!result.ok) {
      throw new Error(`session post failed (status=${result.status} error=${result.error ?? "?"})`);
    }
    return;
  }
  await postReply(reply, tweetId);
}

/** Post one of the generated reply variants */
export async function handleXPost(callbackId: string, replyIndex: number): Promise<string> {
  const entry = pending.get(callbackId);
  if (!entry) return "expired";
  clearTimeout(entry.timeout);
  pending.delete(callbackId);
  const reply = entry.replies[replyIndex] ?? entry.replies[0];
  try {
    await dispatchApprovedPost(reply, entry.tweetId, entry.postingMode ?? "official");
    console.log(`[x-agent] Posted opt ${replyIndex + 1} to @${entry.xUsername} (mode=${entry.postingMode ?? "official"}): ${reply}`);
    await editAdminMessages(entry.msgIds, `✅ *Posted* (opt ${replyIndex + 1})\n\n_${reply}_`);
    return "posted";
  } catch (e: any) {
    console.error(`[x-agent] Failed to post: ${e.message}`);
    await editAdminMessages(entry.msgIds, `⚠️ *Error posting*: ${e.message}`);
    return "error";
  }
}

/** Post a custom (manually edited) reply */
export async function handleXPostCustom(callbackId: string, customReply: string): Promise<string> {
  const entry = pending.get(callbackId);
  if (!entry) return "expired";
  clearTimeout(entry.timeout);
  pending.delete(callbackId);
  const reply = customReply;
  try {
    await dispatchApprovedPost(reply, entry.tweetId, entry.postingMode ?? "official");
    console.log(`[x-agent] Posted custom reply to @${entry.xUsername} (mode=${entry.postingMode ?? "official"})`);
    await editAdminMessages(entry.msgIds, `✅ *Posted* (custom)\n\n_${customReply}_`);
    return "posted";
  } catch (e: any) {
    console.error(`[x-agent] Failed to post custom: ${e.message}`);
    return "error";
  }
}

/** Reject — discard all variants */
export async function handleXReject(callbackId: string): Promise<string> {
  const entry = pending.get(callbackId);
  if (!entry) return "expired";
  clearTimeout(entry.timeout);
  pending.delete(callbackId);
  console.log(`[x-agent] Rejected reply to @${entry.xUsername}`);
  await editAdminMessages(entry.msgIds, `❌ *Rejected* — @${entry.xUsername}`);
  return "rejected";
}

/** Read pending entry (used by Telegram edit flow) */
export function getXPending(callbackId: string) {
  return pending.get(callbackId);
}

// ─── AI System prompt ─────────────────────────────────────────────────────────

const FRONTEND = process.env.FRONTEND_URL || "https://fud.markets";

// Short URL host without protocol — X auto-linkifies bare hostnames and
// stops flagging them as spam-ish when the path is short and clean
// (`fud.markets/<uuid>`). Long `https://fud.markets/market/<uuid>` was
// triggering reports. The new /[id] route bridges to /?market=<id>.
// 2026-05-18 quick fix.
const SHORT_HOST = (process.env.FRONTEND_URL || "https://fud.markets")
  .replace(/^https?:\/\//, "")
  .replace(/\/$/, "");
const shortMarketLink = (id: string) => `${SHORT_HOST}/${id}`;

const SYSTEM = `You are the FUD.markets bot on X (Twitter). You open prediction markets on-chain and direct users to trade on fud.markets.

Rules:
- Replies must be under 270 characters.
- Be concise and functional. No slang, no hype, no filler.
- CRITICAL link rule: when create_market returns "link: <url>" in its tool output, you MUST use that exact URL in your reply. It points to the specific market (e.g. fud.markets/abc123). Never replace it with the homepage. Copy the URL verbatim.
- Only fall back to the homepage fud.markets when there is no market-specific link (e.g. user has no FUD account yet, or autosign isn't enabled).
- Reply in the same language the user wrote in.
- Call create_market AT MOST ONCE per tweet. If a tool result already returned a market link, do not call it again.

All markets are on-chain on Base. There is no paper mode and no manual-sign web fallback — the bot only operates for users with active Autosign. If the user lacks autosign or a FUD account, the tool tells you exactly what reply to send. Relay that copy verbatim; do not invent a "complete on web" CTA.

Token lookup is CA-only. Do not pass tickers like $PEPE — they collapse on the wrong DexScreener match. The user's tweet must contain a contract address (0x... for BASE/ETH or base58 for SOL). If it doesn't, ask them for the CA.

When a user wants to trade (e.g. "long 33eum...pump 1h $5"):
1. (Optional) search_token by CA if you need the live price for the reply.
2. Call create_market once with the CA + chain + timeframe + side + amount + a short tagline (≤60 chars) derived from the tweet.
3. Reply based on what create_market returned:
   - AUTOSIGNED: "Done. <side> $<amount> <symbol> <tf> opened ✅" + the exact link.
   - No-account / no-consent / operational-skip: relay the copy from the tool result verbatim; include only the link the tool gave you (which may be the market-specific link for race-recovery, or no link at all for clean nudges).

If the user is missing required info (CA or timeframe), reply asking:
  "@user need a CA + timeframe — paste the contract and try again (e.g. 33eum...pump 1h)."

Market context (use if relevant):
- You have access to open markets via get_open_markets.
- If a user asks what's hot or trending, use get_open_markets.`;


// ─── Tools ────────────────────────────────────────────────────────────────────

const TOOLS: Anthropic.Tool[] = [
  {
    name: "search_token",
    description: "Look up a token's live price, mcap, and chain by contract address. CA only — do NOT pass tickers or names (they map to the wrong token via DexScreener's first-match). Optional: this tool is only useful if you need the live price for the reply. create_market also takes a CA directly.",
    input_schema: {
      type: "object" as const,
      properties: { query: { type: "string", description: "Contract address — 0x... for EVM or 32-44 char base58 for Solana." } },
      required: ["query"],
    },
  },
  {
    name: "get_open_markets",
    description: "Get the list of currently open prediction markets on FUD.markets",
    input_schema: { type: "object" as const, properties: {} },
  },
  {
    name: "create_market",
    description: "Create a new prediction market for a token. Requires linked FUD account + a contract address (ca). The backend resolves the token symbol from the CA via Dexscreener — do NOT pass a ticker. If side/amount are explicit, include them so the trade autosigns or prefills the position.",
    input_schema: {
      type: "object" as const,
      properties: {
        chain:     { type: "string", description: "One of: SOL, BASE, ETH, BSC, TRON, SUI, MONAD, POLYGON, AVAX, PULSECHAIN, TON, ABSTRACT, HYPEREVM, HOOD. Pick by address shape: base58 32-44 = SOL; T+33 base58 = TRON; 0x+40 hex = EVM (BASE/ETH/BSC/MONAD/POLYGON/AVAX/PULSECHAIN/ABSTRACT/HYPEREVM/HOOD — disambiguate via the tweet context); 0x{module}::name = SUI; EQ/UQ/kQ/0Q+46 base64url = TON." },
        timeframe: { type: "string", description: "15m, 1h, 24h, 1w" },
        ca:        { type: "string", description: "Contract address — format depends on chain (see chain field). REQUIRED." },
        tagline:   { type: "string", description: "Punchy opener message derived from the tweet, max 60 chars" },
        side:      { type: "string", description: "Optional. 'long' or 'short' if the user explicitly stated a direction." },
        amount:    { type: "number", description: "Optional. USD amount the user wants to bet, if explicitly stated." },
      },
      required: ["chain", "timeframe", "ca"],
    },
  },
];

// ─── Tool execution ───────────────────────────────────────────────────────────

// Sentinel returned by create_market on any PRE-creation failure gate
// (no account, no/paused consent, rate limit, below-min, no wallet,
// insufficient balance). The agent loop detects this prefix and aborts
// the whole mention SILENTLY — no tweet is posted. Marcos 2026-05-25:
// "el bot solo contesta a los que SÍ pudieron abrir mercado, lo demás es
// ruido." If a market was NOT created, we never reply. Post-creation
// outcomes (success, bet-didn't-land, consent skip after creation) still
// reply because a market exists on-chain for the user to find.
const SILENT_SKIP = "SILENT_SKIP:";

async function runTool(name: string, input: any, fudUser: any, token: string | null): Promise<string> {
  if (name === "search_token") {
    const q = String(input.query ?? "").trim();
    // CA-only: ticker search collapses on the wrong DexScreener match.
    // Codex P2 2026-05-13. Accept 0x EVM or 32-44 char base58 Solana.
    const isEvmCa = /^0x[a-fA-F0-9]{40}$/.test(q);
    const isSolCa = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(q);
    if (!isEvmCa && !isSolCa) {
      return "Refused: tickers are NOT accepted — pass a contract address (0x... for EVM, base58 for Solana). Tell the user to paste the CA.";
    }
    const url = `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(q)}`;
    const res  = await fetch(url, { headers: { "User-Agent": "FUDMarkets/1.0" } });
    if (!res.ok) return `Token lookup failed: ${res.status}`;
    const data = await res.json() as any;
    const pairs = (data.pairs ?? []).filter((p: any) => p.priceUsd && parseFloat(p.priceUsd) > 0);
    if (!pairs.length) return "Token not found for that CA";
    const best = pairs.sort((a: any, b: any) => (b.liquidity?.usd ?? 0) - (a.liquidity?.usd ?? 0))[0];
    const mcap = best.marketCap ? `$${Number(best.marketCap).toLocaleString()}` : "N/A";
    const ident = await resolveSafeDisplayTicker({ symbol: best.baseToken.symbol, ca: best.baseToken.address ?? q, chain: best.chainId });
    return `${ident.displayTicker} | ${best.chainId} | $${best.priceUsd} | mcap: ${mcap}`;
  }
  if (name === "get_open_markets") {
    const markets = await fetch(`${API}/markets`).then(r => r.json()) as any[];
    if (!markets.length) return "No open markets";
    return markets.slice(0, 5).map((m: any) => `${m.display_ticker ?? m.symbol} ${m.timeframe} L:$${m.long_pool} S:$${m.short_pool}`).join("\n");
  }
  if (name === "create_market") {
    // No linked FUD account — bot operates only with autosign, and
    // autosign requires an account. Send them to sign up.
    if (!token || !fudUser) {
      return `${SILENT_SKIP}no_account`;
    }

    // Autosign gate — Marcos 2026-05-13: the bot only operates for
    // users with autosign. No manual-sign fallback link, no orphan
    // market. If consent is missing, point them at settings and bail
    // before any chain interaction. Pass 9 P2: surface operator pause
    // distinctly so a kill-switch event doesn't accuse the user of an
    // incomplete setup.
    const gate = await checkAutosignGate(fudUser.id);
    if (!gate.ok) {
      return `${SILENT_SKIP}${gate.reason === "feature_disabled" ? "autosign_paused" : "no_consent"}`;
    }

    // Rate limit per user (in-memory bucket). Aplica también al X bot
    // por simetría con Telegram — un abuser podría triggerar muchas
    // creaciones mencionando el bot en spam.
    const rl = checkMarketCreationRateLimit(fudUser.id);
    if (!rl.ok) {
      return `${SILENT_SKIP}rate_limit_${rl.reason}`;
    }

    // V5 lazy markets are opened WITH the opener's position — there is no
    // eager create-without-bet. If the tweet didn't carry a side+amount we
    // can't open a lazy market → silent skip.
    const side   = (input.side === "long" || input.side === "short") ? input.side : null;
    const amount = typeof input.amount === "number" && input.amount > 0 ? input.amount : null;
    if (!side || amount == null) {
      return `${SILENT_SKIP}no_position`;
    }
    // Bot deliberately offers a stricter subset (15m/1h/24h/1w, see the
    // VALID_TIMEFRAMES Set above) than the service's full set — the trading
    // UI can only render trades for these. Not a bug; intentional policy.
    if (!VALID_TIMEFRAMES.has(input.timeframe)) {
      return `${SILENT_SKIP}bad_timeframe`;
    }

    // Resolve token symbol + market cap from the CA, chain-aware (V5 needs a
    // symbol; web resolves it client-side, the bot does it here) + banned guard.
    const meta = await resolveTokenMetaFromCA(input.ca, input.chain);
    if (!meta) {
      return `${SILENT_SKIP}token_not_found`;
    }
    if (await isTokenBanned(input.ca, input.chain)) {
      return `${SILENT_SKIP}banned_token`;
    }

    // Sign the LazyBet intent (Privy) + persist the pending market via the
    // shared V5 core. Balance / cap / consent / nonce are enforced inside.
    // V5 open is binary: success → a pending market exists; any failure →
    // nothing was created. So we reply ONLY on success and silent-skip every
    // failure path (Marcos: el bot solo contesta a los que SÍ abrieron).
    const auto = await tryAutosignLazyMarket({
      userId:    fudUser.id,
      username:  fudUser.username,
      symbol:    meta.symbol,
      chain:     input.chain,
      ca:        input.ca,
      timeframe: input.timeframe as Timeframe,
      side,
      amount,
      tagline:   input.tagline ?? null,
      entryMarketCap: meta.marketCap,
    });
    if (!auto.ok) {
      console.warn(`[x-bot] lazy autosign skip — userId=${fudUser.id} skip=${auto.skip} detail="${auto.detail ?? ""}"`);
      return `${SILENT_SKIP}lazy_${auto.skip}`;
    }
    recordMarketCreation(fudUser.id);
    // "Opened" = the opener's intent is signed + published. The market is
    // pending a taker (never say it's already matched). The link resolves
    // via GET /markets/:id → pending_markets fallback.
    return `OPENED — ${side.toUpperCase()} $${amount} on ${meta.safeDisplayTicker} ${input.timeframe}. `
      + `Reply with: "Opened ✅ ${side} $${amount} ${meta.safeDisplayTicker} ${input.timeframe} — now waiting for someone to take the other side." `
      + `followed by the market link. Do not mention "pending" or tx hashes. | link: ${shortMarketLink(auto.pendingMarketId)}`;
  }
  return "Unknown tool";
}

// ─── Process a single mention ─────────────────────────────────────────────────

async function processMention(tweet: any, opts: { forceRetry?: boolean } = {}) {
  const xUsername = (tweet.author?.userName ?? "").toLowerCase();
  const text      = tweet.text?.replace(/@FUDmarkets/gi, "").trim() ?? "";
  // Use id_str to avoid JS float64 precision loss on 19-digit Twitter snowflake IDs
  const tweetId   = tweet._safeId ?? tweet.id_str ?? String(tweet.id);
  console.log(`[x-agent] Tweet raw id=${tweet.id} id_str=${tweet.id_str} _safeId=${tweet._safeId} → using ${tweetId}`);
  const tweetUrl  = `https://x.com/${xUsername}/status/${tweetId}`;

  // ── Filter FIRST — before claiming a dedup row ──
  // Filtered tweets (rate-limit, blocked user, spam heuristic, etc.)
  // must NEVER claim the dedup row. If they did, an in-flight filter
  // change couldn't re-evaluate them, and the row would be a dead
  // permanent skip. Codex review 2026-05-18 (HIGH).
  const { ok, reason } = await shouldProcess(tweet);
  if (!ok) {
    console.log(`[x-agent] Skipped @${xUsername} — ${reason}`);
    return;
  }

  // Manual retry path (processMentionByUrl). Clear the prior DB claim
  // so the atomic INSERT below is what dedups this attempt (any other
  // concurrent poll still loses the race). Without this, once a row
  // exists, manual retry is a no-op. Codex P2 2026-05-18.
  if (opts.forceRetry) {
    try {
      await db.query(`DELETE FROM x_processed_tweets WHERE tweet_id = $1`, [tweetId]);
    } catch (e: any) {
      console.warn(`[x-agent] forceRetry: failed to clear prior claim for ${tweetId}: ${e?.message ?? e}`);
    }
  }

  // DB-backed dedup (migration v38, Marcos 2026-05-18). processedIds
  // in memory still does first-pass dedup per session — this catches
  // the post-restart case where the Set is empty but the same tweet
  // would otherwise get reprocessed within the 10-min sinceTime
  // window, spawning a duplicate on-chain market. INSERT ... ON
  // CONFLICT DO NOTHING is atomic; rowCount tells us if WE claimed
  // the tweet first.
  let claimed = false;
  try {
    const claim = await db.query(
      `INSERT INTO x_processed_tweets (tweet_id) VALUES ($1)
       ON CONFLICT (tweet_id) DO NOTHING`,
      [tweetId],
    );
    if ((claim.rowCount ?? 0) === 0) {
      console.log(`[x-agent] Skipped @${xUsername} tweet ${tweetId} — already processed in DB (restart-safe dedup)`);
      return;
    }
    claimed = true;
  } catch (e: any) {
    // If the table doesn't exist yet (pre-v38) or DB is down, fall
    // through to in-memory dedup so we don't block the bot entirely.
    console.warn(`[x-agent] DB dedup check failed for ${tweetId}: ${e?.message ?? e} — falling back to in-memory only`);
  }

  // `committed` flips true the moment we take (or even attempt) an
  // externally-visible side effect: a Twitter reply, an on-chain
  // create_market, or pushing a draft to admin Telegram. If we throw
  // BEFORE that point — Anthropic 5xx, transient DB error, etc. — we
  // release the dedup claim so the next poll (or a restart) can retry.
  // Without this release, a transient blip silently burns the mention
  // forever. Codex P2 2026-05-18.
  let committed = false;
  try {

  // ── Trade-intent classification (cheap, no Claude calls) ──
  const intent = parseTradeIntent(text);
  console.log(`[x-agent] @${xUsername} intent=${intent.kind} — "${text.slice(0, 80)}"`);

  // Missing CA — templated nudge, no Claude. CA is the only thing
  // that uniquely identifies a token (tickers are ambiguous).
  // Marcos 2026-05-12.
  // Marcos 2026-05-21: silent-skip on bad input. The bot only ever
  // replies when the trade actually executes. Anything else — wrong
  // format, missing CA, missing timeframe, no account, no autosign —
  // gets ignored. Saves the bot's X reputation (no shadow-ban from
  // explainer spam) and trains users that "if the bot didn't reply,
  // I formatted it wrong" without nudging them on every miss.
  if (intent.kind === "missing_ca") {
    console.log(`[x-agent] silent skip — missing CA from @${xUsername}`);
    return;
  }
  if (intent.kind === "missing_timeframe") {
    console.log(`[x-agent] silent skip — missing timeframe from @${xUsername}`);
    return;
  }

  // No trade intent at all — only the reply-agent path handles these,
  // and it's opt-in. Default OFF saves Claude credits + Telegram noise.
  if (intent.kind === "none") {
    if (!X_REPLY_AGENT_ENABLED) {
      console.log(`[x-agent] reply-agent disabled, skipping non-trade mention`);
      return;
    }
    // Fall through to the legacy Claude+admin-queue flow below.
  }

  console.log(`[x-agent] Processing @${xUsername} (${reason}): ${text}`);

  const fudUser = await getUserByXUsername(xUsername);
  const token   = fudUser ? mintToken(fudUser.id, fudUser.username) : null;

  // Complete trade intent + user NOT linked — silent skip. Marcos
  // 2026-05-21: acquisition funnel was costing us X reputation. The
  // bot stays quiet on every failure path now.
  if (intent.kind === "complete" && !fudUser) {
    console.log(`[x-agent] silent skip — no FUD account for @${xUsername}`);
    return;
  }

  // User has a FUD account linked to X but no active autosign consent
  // (or no embedded wallet yet → also no consent). Silent skip.
  if (intent.kind === "complete" && fudUser) {
    const completeGate = await checkAutosignGate(fudUser.id);
    if (!completeGate.ok) {
      console.log(`[x-agent] silent skip — autosign gate ${completeGate.reason} for @${xUsername}`);
      return;
    }
  }

  // Don't expose balance in the LLM context — it ends up in tweet
  // replies (Marcos 2026-05-13: bot tweeted "balance $0.25" while the
  // user's actual vault was $4.75). The LLM never needed it for trade
  // decisions: balance gating happens server-side in create_market.
  const userContext = fudUser
    ? `\nLinked FUD account: "${fudUser.username}"`
    : `\nNo linked FUD account.`;

  // Fetch market context (top 5 open markets for context)
  let marketContext = "";
  try {
    const markets = await fetch(`${API}/markets`).then(r => r.json()) as any[];
    if (markets.length > 0) {
      const top = markets.slice(0, 5).map((m: any) => `${m.display_ticker ?? m.symbol} ${m.timeframe} L:$${m.long_pool} S:$${m.short_pool}`).join(", ");
      marketContext = `\nActive markets: ${top}`;
    }
  } catch (e: any) { console.error("[x-agent]", e.message ?? e); }

  const messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content: `Tweet from @${xUsername}: "${text}"${userContext}${marketContext}\n\n`
        + `Pre-parsed intent: side=${intent.kind === "complete" ? intent.side : "?"}, `
        + `ca=${intent.kind === "complete" ? intent.ca : "?"}, `
        + `timeframe=${intent.kind === "complete" ? intent.timeframe : "?"}, `
        + `amount=${intent.kind === "complete" && intent.amount ? intent.amount : "?"}. `
        + `Use these EXACT values when calling create_market — do not re-parse. `
        + `The backend will derive symbol from the CA via Dexscreener; just pass ca + chain (BASE for 0x..., SOL for base58) + timeframe.`,
    },
  ];

  let response = await anthropic.messages.create({
    model: "claude-haiku-4-5-20251001", max_tokens: 512,
    system: SYSTEM, tools: TOOLS, messages,
  });

  // Hard cap: create_market is callable AT MOST ONCE per tweet. The
  // system prompt says so but Claude sometimes ignores it after seeing
  // a partial-failure tool result ("market created but bet didn't land")
  // and calls create_market again to "retry" — which creates a second
  // on-chain market for the same tweet, double-charging gas and confusing
  // the user with two replies and two market links. Marcos 2026-05-18.
  let createMarketCalls = 0;
  while (response.stop_reason === "tool_use") {
    const toolUses = response.content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");
    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const t of toolUses) {
      let result: string;
      if (t.name === "create_market") {
        if (createMarketCalls >= 1) {
          // Block the second invocation entirely. Tell Claude to use the
          // prior tool result instead of opening a new market.
          result = "ERROR: create_market already called once for this tweet. Do NOT call it again. Use the previous result's market link in your reply. If the first attempt failed (autosign skip, bet didn't land), reply telling the user what happened and include the market link from the previous tool result.";
          console.warn(`[x-agent] BLOCKED duplicate create_market call for tweet ${tweetId}`);
        } else {
          createMarketCalls += 1;
          committed = true; // on-chain side effect imminent — never release dedup
          try { result = await runTool(t.name, t.input as any, fudUser, token); }
          catch (e: any) { result = `Error: ${e.message}`; }
          // Pre-creation gate tripped → silent skip. No market was opened,
          // so we never reply. Keep the dedup claim (committed already true)
          // so the tweet isn't reprocessed into another silent pass.
          if (result.startsWith(SILENT_SKIP)) {
            console.log(`[x-agent] silent skip — create_market gate ${result.slice(SILENT_SKIP.length)} for @${xUsername}`);
            return;
          }
        }
      } else {
        try { result = await runTool(t.name, t.input as any, fudUser, token); }
        catch (e: any) { result = `Error: ${e.message}`; }
      }
      console.log(`  [tool] ${t.name} → ${result}`);
      results.push({ type: "tool_result", tool_use_id: t.id, content: result });
    }
    messages.push({ role: "assistant", content: response.content });
    messages.push({ role: "user", content: results });
    response = await anthropic.messages.create({
      model: "claude-haiku-4-5-20251001", max_tokens: 512,
      system: SYSTEM, tools: TOOLS, messages,
    });
  }

  const reply = response.content.find((b): b is Anthropic.TextBlock => b.type === "text")?.text ?? "";
  console.log(`  → Reply: ${reply}`);

  // Trade-intent path: auto-post the reply directly. The tool result
  // already gated balance/caps/autosign, the Claude reply is templated
  // ("Done. long $X 1h opened ✅" or fallback link). No admin approval.
  if (intent.kind === "complete") {
    if (reply.trim()) {
      committed = true;
      await postTemplatedReply({ mode: "fixed", text: reply, tweetId, label: "trade_intent" });
    } else {
      console.warn(`[x-agent] empty Claude reply on trade-intent — nothing posted`);
    }
    return;
  }

  // Reply-agent path (only reached when intent.kind === "none" AND
  // X_REPLY_AGENT_ENABLED): admin approval queue for non-trade
  // chitchat. Off by default for cost.
  // ── Send to admin Telegram for approval ──
  const callbackId = `x_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const replies = [reply];

  // Escape chars that Markdown V1 would interpret as entities (underscores in @handles,
  // asterisks, square brackets). Without this, long tweets with many @mentions break
  // Telegram's parser ("can't parse entities").
  const escapeMd = (s: string) => s.replace(/([_*\[\]`])/g, "\\$1");
  const safeText  = escapeMd(text);
  const safeReply = escapeMd(reply);
  const safeUser  = escapeMd(xUsername);
  const notif = `*X mention from @${safeUser}*\n\n_"${safeText}"_\n\n${safeReply}\n\n[View tweet](${tweetUrl})`;

  const keyboard = [
    [
      { text: "✅ Post",    callback_data: `xpost_${callbackId}_0` },
      { text: "✏️ Edit",   callback_data: `xedit_${callbackId}` },
      { text: "❌ Reject", callback_data: `xreject_${callbackId}` },
    ],
  ];

  committed = true; // about to push a draft to admin Telegram (visible side effect)
  const msgIds = await sendToAdminTelegram(notif, keyboard);

  // Codex P1 2026-05-12: if Telegram is in 429 backoff, msgIds is
  // empty — no admin will see this draft. Don't enqueue or burn a
  // 30-min timeout slot in `pending`. Drop the draft, log, and move on.
  if (msgIds.size === 0) {
    console.warn(`[x-agent] dropping draft for @${xUsername} — admin notif failed (backoff or send error)`);
    return;
  }

  // Auto-expire after 30 minutes
  const timeout = setTimeout(async () => {
    if (pending.has(callbackId)) {
      const e = pending.get(callbackId)!;
      pending.delete(callbackId);
      console.log(`[x-agent] Auto-expired reply to @${xUsername}`);
      await editAdminMessages(e.msgIds, `⏱ *Expired* (30min) — @${xUsername}`);
    }
  }, 30 * 60 * 1000);

  setPending(callbackId, { tweetId, xUsername, replies, timeout, msgIds });
  } catch (err: any) {
    // If we threw before committing to any side effect, release the
    // dedup claim so the next poll (or restart) can retry. Once
    // `committed` is true, keep the row — retrying would either
    // double-post a reply or spawn a second on-chain market.
    if (claimed && !committed) {
      try {
        await db.query(`DELETE FROM x_processed_tweets WHERE tweet_id = $1`, [tweetId]);
        console.warn(`[x-agent] released dedup claim for ${tweetId} — failed before side effects: ${err?.message ?? err}`);
      } catch (e: any) {
        console.warn(`[x-agent] failed to release dedup claim for ${tweetId}: ${e?.message ?? e}`);
      }
    } else if (claimed) {
      console.error(`[x-agent] post-commit failure for ${tweetId} — keeping dedup row (side effect already taken): ${err?.message ?? err}`);
    }
    throw err;
  }
}

// ─── Poll loop ────────────────────────────────────────────────────────────────

async function poll() {
  try {
    const now = Math.floor(Date.now() / 1000);
    // Use persisted cursor (lastPollTime) with a small safety overlap.
    // Codex P1 2026-05-12: previously we hardcoded `now - 600` and
    // never wrote lastPollTime, so a restart under burst would replay
    // the entire last 10 minutes and recreate the admin flood. Now we
    // resume from the saved cursor (minus a 60s overlap to absorb API
    // indexing delay). processedIds in-memory still dedupes within a
    // session.
    const sinceTime = Math.max(lastPollTime - 60, now - 600);
    const url = `https://api.twitterapi.io/twitter/user/mentions?userName=${FUDMARKETS_USERNAME}&sinceTime=${sinceTime}`;
    console.log(`[x-agent] polling mentions: sinceTime=${sinceTime}`);
    const res  = await fetch(url, { headers: { "X-API-Key": TWITTERAPI_KEY } });
    if (!res.ok) {
      const body = await res.text();
      console.error(`[x-agent] Poll HTTP ${res.status}: ${body}`);
      return;
    }
    const data = await res.json() as any;
    const mentions: any[] = data.tweets ?? [];
    console.log(`[x-agent] ${new Date().toISOString()} — ${mentions.length} mention(s) | raw keys: ${Object.keys(data).join(",")} | status: ${data.status}`);
    if (mentions.length === 0 && data.status !== "success") console.log(`[x-agent] raw response: ${JSON.stringify(data).slice(0, 300)}`);

    // Filter first WITHOUT marking processed — so anything we cap can be
    // picked up next cycle. We only mark IDs as processed once we commit to
    // sending them through Claude.
    const candidates = mentions.filter((t: any) => {
      const author = (t.author?.userName ?? t.user?.screen_name ?? "").toLowerCase();
      if (author === FUDMARKETS_USERNAME.toLowerCase()) return false;
      const tid = t.id_str ?? String(t.id);
      if (!tid || !/^\d{15,}$/.test(tid)) return false;
      t._safeId = tid;
      return !processedIds.has(tid);
    });

    // Cap per cycle — anything beyond is left for the next poll (NOT marked
    // processed). Prevents a burst of new mentions from spawning 50 Claude
    // calls in one tick.
    const toProcess = candidates.slice(0, MENTIONS_PER_CYCLE_CAP);
    toProcess.forEach((t: any) => processedIds.add(t._safeId));
    const capped = candidates.length > toProcess.length;
    if (capped) {
      console.warn(`[x-agent] mention burst — capped ${candidates.length} → ${toProcess.length} this cycle`);
    }

    if (processedIds.size > 500) {
      const arr = [...processedIds];
      arr.slice(0, arr.length - 500).forEach(id => processedIds.delete(id));
    }

    // Advance the cursor carefully. Codex P1 2026-05-13: previously
    // we set lastPollTime = now unconditionally, which silently
    // dropped leftover mentions when the burst cap kicked in (their
    // createdAt is BEFORE `now`, so the next poll's sinceTime would
    // skip them). When capped, anchor the cursor to the oldest
    // candidate's timestamp - 1s so the next cycle re-fetches the
    // whole window. processedIds dedups what we've already handled,
    // so the leftover slice is picked up without reprocessing.
    let cursorTs = now;
    if (capped) {
      const tsList: number[] = candidates
        .map((t: any) => {
          const raw = t.created_at ?? t.createdAt ?? t.timestamp_ms ?? null;
          if (!raw) return null;
          const ms = typeof raw === "number" ? raw : Date.parse(raw);
          return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
        })
        .filter((n: any): n is number => Number.isFinite(n));
      if (tsList.length > 0) {
        const oldest = Math.min(...tsList);
        cursorTs = Math.max(oldest - 1, lastPollTime); // never go backwards past prior poll
      } else {
        // No usable timestamps — don't advance, refetch same window.
        cursorTs = lastPollTime;
      }
    }
    lastPollTime = cursorTs;
    await saveLastPollTime(cursorTs);

    if (!toProcess.length) return;
    console.log(`[x-agent] ${toProcess.length} new mention(s) to process`);
    for (const tweet of [...toProcess].reverse()) await processMention(tweet);
  } catch (e: any) {
    console.error(`[x-agent] Poll error: ${e.message}`);
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

// ─── Manual mention processing by URL/ID ─────────────────────────────────────
// For tweets that Twitter's /user/mentions endpoint doesn't return
// (e.g. long-form posts where @FUDmarkets appears after the displayTextRange).

export async function processMentionByUrl(urlOrId: string): Promise<{ ok: boolean; message: string }> {
  const idMatch = urlOrId.match(/status\/(\d+)/) ?? urlOrId.match(/^(\d{15,})$/);
  const tweetId = idMatch?.[1];
  if (!tweetId) return { ok: false, message: "Could not extract tweet ID from URL" };
  try {
    const res = await fetch(`https://api.twitterapi.io/twitter/tweets?tweet_ids=${tweetId}`, {
      headers: { "X-API-Key": TWITTERAPI_KEY },
    });
    if (!res.ok) return { ok: false, message: `twitterapi.io returned ${res.status}` };
    const data = await res.json() as any;
    const tweet = (data.tweets ?? [])[0];
    if (!tweet) return { ok: false, message: "Tweet not found" };
    // Manual calls bypass session-level + DB dedup — user explicitly
    // asked for this tweet. forceRetry deletes any existing claim row
    // so the atomic INSERT inside processMention truly re-claims it.
    processedIds.delete(tweetId);
    tweet._safeId = tweetId;
    await processMention(tweet, { forceRetry: true });
    return { ok: true, message: `Queued reply for tweet ${tweetId} from @${tweet.author?.userName ?? "?"} — check admin chat to approve` };
  } catch (e: any) {
    return { ok: false, message: `Error: ${e.message ?? String(e)}` };
  }
}

// ─── Proactive draft (KOL reply guy flow) ────────────────────────────────────
// Reads the target tweet (text + images) and asks Claude (Haiku 4.5 with vision)
// to draft a reply in "reply guy" voice. Sends to admin Telegram for approval.
// On Post, dispatchApprovedPost routes through postViaSession (x-poster bypass)
// because the official API blocks proactive replies.

const REPLY_GUY_SYSTEM = `You are a crypto-Twitter native posting from @FUDmarkets — a prediction markets app. You are replying to someone else's tweet. A human will approve before it ships, so be sharp.

Rules:
- Maximum 270 characters. Twitter cuts you off.
- Voice: witty, observational, native crypto Twitter. NO corporate, NO sycophancy, NO "this aged well" / "fr" / "ngmi" filler.
- Match the tweet's language. If the tweet is Spanish, reply Spanish.
- DO NOT plug fud.markets unless the tweet specifically discusses a token that has an active market on FUD. Most replies should be pure banter / takes.
- DO NOT start with "@username" (Twitter auto-prepends) and DO NOT use hashtags.
- Vary structure across replies: contrarian take, sharp observation, dry joke, provocative question, concrete chart read. Avoid formulaic.
- If the tweet has an image (chart, screenshot, meme), reference what's actually in it.
- If a steering hint is given (e.g. "bullish", "meme", "serio", "duda"), lean into that vibe while keeping your voice.

Output: just the reply text. No quotes, no preamble, no explanation.`;

// Hostname allowlist for image URLs forwarded to Claude vision.
// Forwarding an attacker-controlled URL to Claude's outbound fetch is an SSRF
// vector — we only accept Twitter's own CDN hostnames.
const ALLOWED_IMAGE_HOSTS = new Set<string>([
  "pbs.twimg.com",
  "ton.twimg.com",
  "video.twimg.com",
]);

function isSafeImageUrl(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return false;
    return ALLOWED_IMAGE_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

function extractTweetImageUrls(tweet: any): string[] {
  const urls: string[] = [];
  const sources = [
    tweet?.media,
    tweet?.entities?.media,
    tweet?.extendedEntities?.media,
    tweet?.extended_entities?.media,
  ];
  for (const src of sources) {
    if (!Array.isArray(src)) continue;
    for (const m of src) {
      const url = m?.media_url_https ?? m?.media_url ?? m?.url;
      if (
        typeof url === "string" &&
        /\.(jpe?g|png|gif|webp)(\?|$)/i.test(url) &&
        isSafeImageUrl(url)
      ) {
        urls.push(url);
      }
    }
  }
  return [...new Set(urls)].slice(0, 2); // dedup, max 2 images (cost / latency)
}

export async function draftProactiveReply(
  urlOrId:  string,
  steering?: string,
): Promise<{ ok: boolean; message: string }> {
  const idMatch = urlOrId.match(/status\/(\d+)/) ?? urlOrId.match(/^(\d{15,})$/);
  const tweetId = idMatch?.[1];
  if (!tweetId) return { ok: false, message: "Could not extract tweet ID from URL" };

  try {
    const fetchRes = await fetch(`https://api.twitterapi.io/twitter/tweets?tweet_ids=${tweetId}`, {
      headers: { "X-API-Key": TWITTERAPI_KEY },
    });
    if (!fetchRes.ok) return { ok: false, message: `twitterapi.io returned ${fetchRes.status}` };
    const data  = await fetchRes.json() as any;
    const tweet = (data.tweets ?? [])[0];
    if (!tweet) return { ok: false, message: "Tweet not found" };

    const author    = String(tweet.author?.userName ?? "?").toLowerCase();
    const tweetText = String(tweet.text ?? "").trim();
    const imageUrls = extractTweetImageUrls(tweet);
    if (!tweetText && imageUrls.length === 0) {
      return { ok: false, message: "Tweet has neither text nor images — nothing to reply to" };
    }

    // Build content array (vision + text)
    const contentBlocks: Anthropic.ContentBlockParam[] = [];
    for (const url of imageUrls) {
      contentBlocks.push({
        type:   "image",
        source: { type: "url", url } as any,
      });
    }
    const promptText =
      `Tweet from @${author}:\n"${tweetText || "(no text — reply must reference the image)"}"` +
      (steering ? `\n\nSteering hint: lean into "${steering}" vibe.` : "");
    contentBlocks.push({ type: "text", text: promptText });

    // Call Claude. Only retry on errors clearly caused by image processing
    // (bad URL, unsupported media). Rate limits, auth, overload errors should
    // bubble up so we don't double-bill or mask the root cause.
    let reply = "";
    try {
      const response = await anthropic.messages.create({
        model:      "claude-haiku-4-5-20251001",
        max_tokens: 300,
        system:     REPLY_GUY_SYSTEM,
        messages:   [{ role: "user", content: contentBlocks }],
      });
      reply = response.content.find((b): b is Anthropic.TextBlock => b.type === "text")?.text?.trim() ?? "";
    } catch (e: any) {
      const errMsg  = String(e?.message ?? e).toLowerCase();
      const errType = String(e?.error?.type ?? e?.type ?? "").toLowerCase();
      const isImageError =
        imageUrls.length > 0 &&
        errType === "invalid_request_error" &&
        /(image|media|url|fetch|download|content.?type)/i.test(errMsg);
      if (!isImageError) throw e;
      console.warn(`[x-agent] vision draft failed (image issue), retrying text-only`);
      const response = await anthropic.messages.create({
        model:      "claude-haiku-4-5-20251001",
        max_tokens: 300,
        system:     REPLY_GUY_SYSTEM,
        messages:   [{ role: "user", content: promptText }],
      });
      reply = response.content.find((b): b is Anthropic.TextBlock => b.type === "text")?.text?.trim() ?? "";
    }

    if (!reply) return { ok: false, message: "Empty draft from Claude" };
    if (reply.length > 280) reply = reply.slice(0, 277) + "...";

    // Send to admin Telegram with approve/edit/reject buttons
    const callbackId = `xd_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const tweetUrl   = `https://x.com/${author}/status/${tweetId}`;

    const escapeMd = (s: string) => s.replace(/([_*\[\]`])/g, "\\$1");
    const safeText   = escapeMd(tweetText.slice(0, 280));
    const safeReply  = escapeMd(reply);
    const safeAuthor = escapeMd(author);
    const steeringLine = steering ? `\nSteering: _${escapeMd(steering)}_` : "";
    const imgLine      = imageUrls.length > 0 ? `\n📷 ${imageUrls.length} image(s) considered` : "";
    const notif =
      `*Proactive draft for @${safeAuthor}*${steeringLine}${imgLine}\n\n` +
      `_"${safeText}"_\n\n` +
      `*Draft:* ${safeReply}\n\n` +
      `[View tweet](${tweetUrl})`;

    const keyboard = [[
      { text: "✅ Post",   callback_data: `xpost_${callbackId}_0` },
      { text: "✏️ Edit",   callback_data: `xedit_${callbackId}` },
      { text: "❌ Reject", callback_data: `xreject_${callbackId}` },
    ]];

    const msgIds = await sendToAdminTelegram(notif, keyboard);

    // Codex P1 2026-05-12: drop proactive draft if Telegram is in
    // 429 backoff. No admin will see it, don't spend a pending slot.
    if (msgIds.size === 0) {
      console.warn(`[x-agent] dropping proactive draft for @${author} — admin notif failed (backoff or send error)`);
      return { ok: false, message: "admin notif failed" };
    }

    const timeout = setTimeout(async () => {
      if (pending.has(callbackId)) {
        const entry = pending.get(callbackId)!;
        pending.delete(callbackId);
        await editAdminMessages(entry.msgIds, `⏱ *Expired* (30min) — proactive draft for @${safeAuthor}`);
      }
    }, 30 * 60 * 1000);

    setPending(callbackId, {
      tweetId,
      xUsername:   author,
      replies:     [reply],
      timeout,
      msgIds,
      postingMode: "session", // critical: route Post button through x-poster bypass
    });

    return { ok: true, message: `Draft for @${author} sent — check admin chat to approve.` };
  } catch (e: any) {
    return { ok: false, message: `Error: ${(e?.message ?? String(e)).slice(0, 300)}` };
  }
}

// ─── Quote-tweet polling ──────────────────────────────────────────────────────
// Quotes of @FUDmarkets's own tweets count as "summon" per X's reply policy
// (POST /2/tweets allows reply when the original author quoted us). The
// /user/mentions endpoint does NOT consistently surface quotes, so we poll
// /tweet/quotes for each of our recent tweets directly.

const FUD_TWEETS_LIMIT      = 20;            // monitor last N tweets for quote activity
const FUD_TWEETS_REFRESH_MS = 15 * 60 * 1000; // refresh own-tweets cache every 15 min

let fudTweetIdsCache: string[] = [];
let lastFudTweetsRefresh        = 0;

async function refreshFudTweetIds(): Promise<void> {
  try {
    const url = `https://api.twitterapi.io/twitter/user/last_tweets?userName=${FUDMARKETS_USERNAME}`;
    const res = await fetch(url, {
      headers: { "X-API-Key": TWITTERAPI_KEY },
      signal:  AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      console.error(`[x-agent] refreshFudTweetIds HTTP ${res.status}`);
      return;
    }
    const data         = await res.json() as any;
    const tweets: any[] = data.tweets ?? data.data ?? [];
    const ids          = tweets
      .map((t: any) => t.id_str ?? String(t.id))
      .filter((id: string) => /^\d{15,}$/.test(id))
      .slice(0, FUD_TWEETS_LIMIT);
    if (ids.length > 0) {
      fudTweetIdsCache       = ids;
      lastFudTweetsRefresh   = Date.now();
      console.log(`[x-agent] cached ${ids.length} FUDmarkets tweet IDs for quote polling`);
    } else {
      console.log(`[x-agent] refreshFudTweetIds: no tweets returned`);
    }
  } catch (e: any) {
    console.error(`[x-agent] refreshFudTweetIds error: ${e?.message ?? e}`);
  }
}

async function pollQuotes(): Promise<void> {
  try {
    if (fudTweetIdsCache.length === 0 || Date.now() - lastFudTweetsRefresh > FUD_TWEETS_REFRESH_MS) {
      await refreshFudTweetIds();
    }
    if (fudTweetIdsCache.length === 0) return;

    // Collect ALL candidate quotes across our cached tweets WITHOUT marking
    // them processed yet. Then cap the cycle, so a viral burst on one of our
    // tweets doesn't dump 50 drafts at the admin in one minute.
    let cycleBudget = QUOTES_PER_CYCLE_CAP;
    let totalNew    = 0;
    let totalSeen   = 0;

    for (const tweetId of fudTweetIdsCache) {
      if (cycleBudget <= 0) break;

      const url = `https://api.twitterapi.io/twitter/tweet/quotes?tweetId=${tweetId}`;
      let res: Response;
      try {
        res = await fetch(url, {
          headers: { "X-API-Key": TWITTERAPI_KEY },
          signal:  AbortSignal.timeout(10_000),
        });
      } catch (e: any) {
        console.error(`[x-agent] quote fetch error for ${tweetId}: ${e?.message ?? e}`);
        continue;
      }
      if (!res.ok) {
        if (res.status === 404) continue;
        console.error(`[x-agent] /tweet/quotes HTTP ${res.status} for ${tweetId}`);
        continue;
      }
      const data           = await res.json() as any;
      const quotes: any[]  = data.tweets ?? data.data ?? [];
      if (quotes.length === 0) continue;

      const candidates = quotes.filter((t: any) => {
        const author = (t.author?.userName ?? t.user?.screen_name ?? "").toLowerCase();
        if (author === FUDMARKETS_USERNAME.toLowerCase()) return false;
        const qid = t.id_str ?? String(t.id);
        if (!qid || !/^\d{15,}$/.test(qid)) return false;
        t._safeId = qid;
        return !processedIds.has(qid);
      });
      totalSeen += candidates.length;
      if (candidates.length === 0) continue;

      // Take up to cycleBudget from this tweet's quotes. Mark + process one
      // at a time so an early throw or break doesn't strand IDs in
      // `processedIds` that never reached processMention.
      const take = candidates.slice(0, cycleBudget);
      console.log(`[x-agent] up to ${take.length} new quote(s) of tweet ${tweetId} (budget left=${cycleBudget})`);
      for (const quote of [...take].reverse()) {
        const qid = quote._safeId;
        try {
          processedIds.add(qid);
          await processMention(quote);
          cycleBudget--;
          totalNew++;
        } catch (e: any) {
          // Mention errored — leave it marked as processed (don't loop) but log.
          console.error(`[x-agent] processMention threw on quote ${qid}: ${e?.message ?? e}`);
        }
        if (cycleBudget <= 0) break;
      }
      if (cycleBudget <= 0) break;
    }
    if (totalSeen > totalNew) {
      console.warn(`[x-agent] quote burst — capped ${totalSeen} → ${totalNew} this cycle`);
    }
    if (totalNew > 0) {
      console.log(`[x-agent] pollQuotes: ${totalNew} new quote(s) processed total`);
    }
    // NOTE: trim of processedIds happens in poll() (mention loop). Both loops
    // share the same Set — single-trim avoids race where pollQuotes evicts
    // mention IDs that haven't been seen yet (and vice-versa).
  } catch (e: any) {
    console.error(`[x-agent] pollQuotes error: ${e?.message ?? e}`);
  }
}

let xAgentStarted = false;
export async function startXAgent() {
  if (!TWITTERAPI_KEY) { console.log("[x-agent] TWITTERAPI_KEY not set — skipping"); return; }
  if (xAgentStarted) {
    console.warn("[x-agent] startXAgent called twice — ignoring");
    return;
  }
  xAgentStarted = true;
  const replyAgent = X_REPLY_AGENT_ENABLED ? "ON" : "OFF (trade-intent-only)";
  const quotes     = X_QUOTES_ENABLED      ? "ON" : "OFF";
  console.log(`[x-agent] Starting — monitoring @FUDmarkets | mentions every ${MENTION_POLL_MS / 1000}s | reply_agent=${replyAgent} | quotes=${quotes}`);
  await loadLastPollTime();
  await poll();
  setInterval(poll, MENTION_POLL_MS);

  // Quote polling — opt-in via X_QUOTES_ENABLED=1. The endpoint costs
  // 1 API call per cached FUDmarkets tweet per cycle (up to 20). For
  // cost-sensitive operation we leave it off by default.
  if (X_QUOTES_ENABLED) {
    setTimeout(() => {
      pollQuotes().catch((e) => console.error(`[x-agent] initial pollQuotes error: ${e?.message ?? e}`));
      setInterval(pollQuotes, QUOTE_POLL_MS);
    }, 30_000);
  }

  // Heartbeat — proves the agent process is alive even when poll cycles produce
  // no new tweets. Without this we depend on traffic to know the bot is up.
  setInterval(() => {
    const tgBackoff = telegramBackoffUntil > Date.now()
      ? `${Math.ceil((telegramBackoffUntil - Date.now()) / 1000)}s`
      : "off";
    console.log(`[x-agent] heartbeat pending=${pending.size} processedIds=${processedIds.size} fudTweetIds=${fudTweetIdsCache.length} tgBackoff=${tgBackoff}`);
  }, 5 * 60_000);
}
