import { Telegraf, Markup } from "telegraf";
import { message } from "telegraf/filters";
import { db } from "../db/client.js";
import { createHmac, randomBytes } from "node:crypto";
import Anthropic from "@anthropic-ai/sdk";
import { handleXPost, handleXPostCustom, handleXReject, getXPending, processMentionByUrl, postReply, postViaSession, draftProactiveReply } from "./x.js";
import { checkVaultBalanceV5, checkMarketCreationRateLimit, recordMarketCreation, isTokenBanned, resolveTokenMetaFromCA } from "./botGuards.js";
import { resolveSafeDisplayTicker } from "../services/tokenIdentity.js";
import { tryAutosignLazyMarket, tryAutosignLazyTake, tryAutosignQueuedBet, checkAutosignGate } from "../services/autosignService.js";
import { LAZY_ENV } from "../services/lazyMarketService.js";
import { marketFeeBps, type Timeframe } from "../lib/market.js";

const API = process.env.BACKEND_URL || "http://localhost:3001";
const BOT_TOKEN = process.env.BOT_TOKEN;
const FRONTEND_URL = process.env.FRONTEND_URL ?? "https://fud.markets";

// Chain map: dexscreener chainId → our backend chain label
const CHAIN_MAP: Record<string, string> = {
  solana:   "SOL",
  base:     "BASE",
  ethereum: "ETH",
  bsc:      "BSC",
  tron:       "TRON",
  sui:        "SUI",
  monad:      "MONAD",
  polygon:    "POLYGON",
  avalanche:  "AVAX",
  pulsechain: "PULSECHAIN",
  ton:        "TON",
  abstract:   "ABSTRACT",
  hyperevm:   "HYPEREVM", robinhood: "HOOD",
};

// Match the timeframes the frontend offers for trading (15m / 1h / 24h / 1w).
// 1m and 5m are silenced (too short to be tradeable in practice); 1w added.
// Marcos 2026-05-25.
const TIMEFRAMES = ["15m", "1h", "24h", "1w"];

// In-memory sessions: tgId → { token, userId, username }
const sessions = new Map<number, { token: string; userId: string; username: string }>();

// X agent edit mode: tgId → { callbackId, customReply? }
const pendingXEdits = new Map<number, { callbackId: string; customReply?: string }>();

// Pending trade state: tgId → token info waiting for TF/side/amount selection
interface PendingTrade {
  symbol: string;
  // Display ticker to show users: canonical for a real primary/alias (cbBTC→
  // "BTC"), else the raw symbol. Impostors render raw too (no badge is the
  // signal; the flow keys identity/price by CA, not symbol).
  safeDisplayTicker: string;
  chain: string;   // SOL / BASE / ETH / BSC
  ca: string;
  price: number;
  liquidity: number;
  volume24h: number;
  marketCap: number;
  name: string;
  timeframe?: string;
  side?: string;
  amount?: number;
  awaitingMsg?: boolean; // waiting for user to type a tagline or skip
  flowMsgId?: number;    // message_id of the flow card (to edit after typing)
  groupChatId?: number;  // if search came from a group, post card there after opening
}
const pendingTrades = new Map<number, PendingTrade>();

// Per-user bet presets: tgId → [amt1, amt2, amt3, amt4]
const userPresets = new Map<number, number[]>();
const DEFAULT_PRESETS = [5, 25, 100, 500];
function getPresets(tgId: number): number[] {
  return userPresets.get(tgId) ?? DEFAULT_PRESETS;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function apiFetch(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers ?? {}) },
  });
  const body = await res.json() as any;
  if (!res.ok) throw new Error(body?.error ?? `HTTP ${res.status}`);
  return body;
}

function mintToken(userId: string, username: string): string {
  const secret  = process.env.JWT_SECRET!;
  const header  = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ userId, username })).toString("base64url");
  const sig     = createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${sig}`;
}

interface TgFrom { id: number; username?: string; first_name: string }

/** Returns session if account exists, null if user needs to register first */
async function getSession(tgId: number): Promise<{ token: string; userId: string; username: string } | null> {
  if (sessions.has(tgId)) return sessions.get(tgId)!;
  const { rows: [existing] } = await db.query(
    `SELECT id, username FROM users WHERE telegram_id = $1`, [tgId]
  );
  if (!existing) return null;
  const token = mintToken(existing.id, existing.username);
  const session = { token, userId: existing.id, username: existing.username };
  sessions.set(tgId, session);
  return session;
}

/** Create account with chosen username, returns error string or null on success */
async function registerUser(tgId: number, username: string): Promise<{ session: { token: string; userId: string; username: string } } | { error: string }> {
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return { error: "Invalid username. Only letters, numbers and _ (3-20 chars)." };
  }
  const { rows: [taken] } = await db.query(`SELECT 1 FROM users WHERE username = $1`, [username.toLowerCase()]);
  if (taken) return { error: `❌ "${username}" is already taken. Try another.` };

  const { rows: [newUser] } = await db.query(
    `INSERT INTO users (username, telegram_id)
     VALUES ($1, $2) RETURNING id, username`,
    [username.toLowerCase(), tgId]
  );
  const token = mintToken(newUser.id, newUser.username);
  const session = { token, userId: newUser.id, username: newUser.username };
  sessions.set(tgId, session);
  return { session };
}

function formatPrice(n: number): string {
  if (n >= 1) return n.toFixed(4);
  const s = n.toFixed(12).replace(/0+$/, "");
  const match = s.match(/^0\.(0+)/);
  if (match) {
    const zeros = match[1].length;
    if (zeros >= 4) return `0.0{${zeros}}${s.slice(2 + zeros, 2 + zeros + 4)}`;
  }
  return n.toPrecision(4);
}

function formatNum(n: number): string {
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000)     return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)         return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

// ─── AI Agent ─────────────────────────────────────────────────────────────────

const anthropic = process.env.ANTHROPIC_API_KEY
  ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY })
  : null;

// Conversation history per user (last 20 turns)
const chatHistory = new Map<number, Anthropic.MessageParam[]>();

function pushHistory(tgId: number, role: "user" | "assistant", content: string) {
  const h = chatHistory.get(tgId) ?? [];
  h.push({ role, content });
  if (h.length > 20) h.splice(0, h.length - 20);
  chatHistory.set(tgId, h);
}

// Phase controls what the bot reveals about the project.
// Set via FUD_PHASE env var: CLOSED | S1 | S2 | S3 | PUBLIC
const FUD_PHASE = (process.env.FUD_PHASE ?? "CLOSED").toUpperCase();

// Internal context the bot KNOWS but doesn't leak.
// Use this to answer questions accurately IF you can confirm the user is a participant,
// and to maintain consistency across conversations. Never dump this to strangers.
const SESSION_INTERNAL_CONTEXT = `
INTERNAL CONTEXT (not for public — for your awareness):
- Session 1 is the first closed session. Invite-only, 10-15 people.
- Format: ~25 min, 4 rounds × 5 min each. Short memecoin markets.
- Real USDC on Base. Bets and payouts are real money.
- Marcos (founder) funds each participant with $5 to play. Top PnL wins $20 extra.
- Condition to keep the $5: play ≥2 rounds + stake ≥$3 total across the session.
- No token, no airdrop, no referrals in Session 1. Pure product test.
- Coordination via private Telegram group + X follow, announced 1:1 to friends.
`;

const PHASE_INFO: Record<string, string> = {
  CLOSED: `Current phase: CLOSED beta (Session 1 prep).

What you can say (tease, don't pitch):
- "Something's cooking. Closed sessions with invited players. You'll see."
- "Prediction market thing. Long or short, memecoins, short rounds. That's all you get."
- If pressed on joining: "Invite-only for now. The real thing opens after we've run a few."

What you CANNOT reveal:
- Specific dates, times, or timelines
- Incentive amounts ($5, $20, etc.) — if asked, just say "the friends invited know the deal"
- Chain details (Base, contracts, vault addresses)
- Referral/token plans (there are none for S1, but don't confirm absence either)
- Number of participants or who's in
- Anything from the INTERNAL CONTEXT above, unless the user clearly shows they're already a participant (e.g., they reference a specific detail like "I got my $5, now what?")

If a user CLEARLY is a participant (mentions the session, the $5, the rounds, etc.), you can help them with mechanics — stake rules, how to bet, how payouts work. Use INTERNAL CONTEXT to stay accurate.

If a random user asks "how do I get in?": redirect them mysteriously. "The right ones find out on their own." / "If you know, you know." Do not give instructions.`,

  S1: `Current phase: post-Session 1.
You can reveal everything from CLOSED plus:
- "We ran our first session with a closed group. Went well."
- Session format in general terms (short rounds, real money, closed group).
- "Second session coming."

Still hold back: exact dates, token plans, future mechanics.`,

  S2: `Current phase: post-Session 2.
You can reveal everything from S1 plus:
- "We ran two closed sessions. Third one opening up soon."
- Detailed mechanics of sessions when asked.

Still don't reveal token/referral plans or exact launch dates.`,

  S3: `Current phase: post-Session 3.
You can reveal everything from S2 plus:
- "Getting close to open beta."
- Mention that sessions have been growing and the product works.

Still hold back on token/referral details.`,

  PUBLIC: `Current phase: PUBLIC.
Product is live, talk freely about it. Still don't reveal internal infrastructure (chains, contracts, operator wallets).`,
};

const AI_SYSTEM = `You are the FUD.markets Telegram bot. Functional only — no chitchat, no personality, no emojis.

REPLY STYLE:
- 1-2 sentences max. Direct.
- Spanish if the user writes in Spanish, English otherwise.
- Never greet, never hype, never invent. Answer or ask the next required field.

CRITICAL — TOKEN LOOKUPS (TICKERS LIE):
- NEVER call search_token with a ticker (e.g. "PEPE", "$DOGE", "hanta"). Multiple tokens share tickers and you will pick the wrong one.
- The ONLY valid input to search_token is a contract address (CA): 0x + 40 hex for EVM, or 43-44 char base58 for Solana.
- If the user gives a ticker or token name, do NOT guess. Reply asking for the CA. Example: "Necesito el CA del token (no el ticker). Pegámelo."
- If search_token returns a "Refused" message, that means you sent a non-CA — apologize briefly and ask the user for the CA.

WHAT YOU CAN DO:
- Help users find open markets via get_open_markets.
- Point users at /markets and /me commands.
- After the user pastes a CA, you can call search_token and report price + market cap.

WHAT YOU DO NOT DO:
- No financial advice, no opinions on whether a token will pump or dump.
- Do not reveal launch dates, internal infrastructure, or product roadmap.
- Do not answer off-topic questions — redirect to /markets.

Keep it boring and useful.`;

async function getAIReply(
  tgId: number,
  userMessage: string,
  session: { token: string; userId: string; username: string } | null,
): Promise<string> {
  if (!anthropic) return "gm ser 🫡 (ANTHROPIC_API_KEY not configured)";

  pushHistory(tgId, "user", userMessage);

  const tools: Anthropic.Tool[] = [
    {
      name: "get_open_markets",
      description: "Fetch the currently open prediction markets on FUD.markets",
      input_schema: { type: "object" as const, properties: {}, required: [] },
    },
    {
      name: "search_token",
      description: "Look up a crypto token by its contract address (CA) to get price + market cap. Tickers are NOT accepted — they map to the wrong token. Only call this once the user has provided a CA: 0x + 40 hex for EVM, or 43-44 char base58 for Solana.",
      input_schema: {
        type: "object" as const,
        properties: {
          query: { type: "string", description: "Contract address only. 0x... for EVM (40 hex) or base58 for Solana (43-44 chars). Never a ticker." },
        },
        required: ["query"],
      },
    },
  ];

  if (session) {
    tools.push({
      name: "get_user_balance",
      description: "Get the current user's account info and a link to check their balance on the web app",
      input_schema: { type: "object" as const, properties: {}, required: [] },
    });
  }

  const messages: Anthropic.MessageParam[] = chatHistory.get(tgId) ?? [];

  // Agentic loop: keep going while Claude wants to use tools
  let currentMessages = [...messages];
  for (let turn = 0; turn < 5; turn++) {
    const response = await anthropic.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 400,
      system: AI_SYSTEM,
      tools,
      messages: currentMessages,
    });

    if (response.stop_reason !== "tool_use") {
      const text = response.content.find((b): b is Anthropic.TextBlock => b.type === "text")?.text ?? "gm ser 🫡";
      pushHistory(tgId, "assistant", text);
      return text;
    }

    // Execute all requested tools
    const assistantMsg: Anthropic.MessageParam = { role: "assistant", content: response.content };
    const toolResults: Anthropic.ToolResultBlockParam[] = [];

    for (const block of response.content) {
      if (block.type !== "tool_use") continue;

      let result = "";
      try {
        if (block.name === "get_open_markets") {
          const markets = await apiFetch("/markets");
          const open = (markets as any[]).filter((m) => m.status === "open").slice(0, 6);
          result = open.length === 0
            ? "No open markets right now."
            : open.map((m) => `• ${m.display_ticker ?? m.symbol} ${m.timeframe} — pool $${(parseFloat(m.long_pool) + parseFloat(m.short_pool)).toFixed(0)}`).join("\n");
        } else if (block.name === "search_token") {
          const q = ((block.input as any).query as string ?? "").trim();
          if (!looksLikeCA(q)) {
            // Hard gate: tickers and free-text queries collapse onto the
            // wrong token (e.g. user typed "$hanta" — DexScreener will
            // pick any random match). Force the LLM back to the user.
            result = `Refused: "${q}" is not a contract address. Tell the user you need a CA (0x... for EVM, base58 for Solana) — never report data based on a ticker.`;
          } else {
            const token = await searchToken(q);
            result = token
              ? `${token.safeDisplayTicker ?? token.symbol} on ${token.chain} | price $${formatPrice(token.price)} | mcap ${token.marketCap > 0 ? formatNum(token.marketCap) : "unknown"}`
              : `CA "${q}" not found on DexScreener.`;
          }
        } else if (block.name === "get_user_balance" && session) {
          result = `User: ${session.username} | Check your balance and positions at ${FRONTEND_URL}`;
        }
      } catch (e: any) {
        result = `Error: ${e.message}`;
      }

      toolResults.push({ type: "tool_result", tool_use_id: block.id, content: result });
    }

    currentMessages = [...currentMessages, assistantMsg, { role: "user", content: toolResults }];
  }

  return "ngmi ser, something broke 😅";
}

// True only when text matches a real on-chain contract address shape:
//   EVM:    0x + 40 hex chars                          (Base, Ethereum, BSC, …)
//   Solana: 43-44 base58 chars (alphabet excludes 0,O,I,l) — 32-byte pubkey
// URLs/handles/random strings fail because they include `/ : ? = . -`,
// which are neither base58 nor hex. The 43-char floor avoids false-positive
// matches on shorter all-base58 strings (e.g. uppercase tickers).
function looksLikeCA(text: string): boolean {
  const t = text.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(t)) return true;
  if (/^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(t)) return true;
  return false;
}

// DexScreener fetch with retry+backoff on 429 and a 60s in-process
// cache. Mirrors the oracle.ts pattern. Previously the bot's
// searchToken did a single bare fetch and surfaced "DexScreener 429"
// raw to the user — Codex 2026-05-13. The same CA pinged twice in a
// short window would hit the rate limit; second call seconds later
// worked because the limit cleared. With retry+cache the user never
// sees the 429.
const _dexCache = new Map<string, { data: any; ts: number }>();
const DEX_CACHE_TTL_MS = 60_000;

async function dexFetchCached(url: string): Promise<any> {
  const cached = _dexCache.get(url);
  if (cached && Date.now() - cached.ts < DEX_CACHE_TTL_MS) return cached.data;

  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(url, { headers: { "User-Agent": "FUDmarkets/1.0" } });
    if (res.status === 429) {
      const wait = (attempt + 1) * 2000;
      console.warn(`[bot] DexScreener 429 — retrying in ${wait}ms (attempt ${attempt + 1}/3)`);
      await new Promise(r => setTimeout(r, wait));
      continue;
    }
    if (!res.ok) throw new Error(`DexScreener ${res.status}`);
    const data = await res.json();
    _dexCache.set(url, { data, ts: Date.now() });
    return data;
  }
  throw new Error(`DexScreener busy — try again in a moment`);
}

async function searchToken(query: string): Promise<PendingTrade | null> {
  const isCA = looksLikeCA(query);
  const url = isCA
    ? `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(query.trim())}`
    : `https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(query.trim())}`;

  console.log(`[bot] DexScreener fetch: ${url}`);
  const data = await dexFetchCached(url) as any;
  let pairs: any[] = data.pairs ?? [];
  console.log(`[bot] Pairs found: ${pairs.length}`);
  if (pairs.length === 0) return null;

  // If CA search, filter to exact address match to avoid cross-chain confusion
  if (isCA) {
    const addr = query.trim().toLowerCase();
    const exact = pairs.filter((p: any) => p.baseToken?.address?.toLowerCase() === addr);
    if (exact.length > 0) pairs = exact;
  }

  const withPrice = pairs.filter((p: any) => p.priceUsd && parseFloat(p.priceUsd) > 0);
  if (withPrice.length === 0) return null;

  // Pick best pair: highest liquidity
  const best = withPrice.sort((a: any, b: any) => (b.liquidity?.usd ?? 0) - (a.liquidity?.usd ?? 0))[0];
  const chain = CHAIN_MAP[best.chainId] ?? best.chainId.toUpperCase();
  const ident = await resolveSafeDisplayTicker({ symbol: best.baseToken.symbol, ca: best.baseToken.address, chain });

  return {
    symbol:    best.baseToken.symbol,
    safeDisplayTicker: ident.displayTicker,
    chain,
    ca:        best.baseToken.address,
    price:     parseFloat(best.priceUsd),
    liquidity: best.liquidity?.usd ?? 0,
    volume24h: best.volume?.h24 ?? 0,
    marketCap: best.marketCap ?? best.fdv ?? 0,
    name:      best.baseToken.name,
  };
}

function groupTokenMessage(t: PendingTrade): string {
  return (
    `🪙 *${t.safeDisplayTicker ?? t.symbol}* — ${t.name}\n` +
    `⛓ Chain: ${t.chain}\n` +
    `💰 Price: $${formatPrice(t.price)}\n` +
    `📈 MCap: ${t.marketCap > 0 ? formatNum(t.marketCap) : "—"}\n` +
    `💧 Liq: ${formatNum(t.liquidity)}\n` +
    `📊 Vol 24h: ${formatNum(t.volume24h)}`
  );
}

function tokenMessage(t: PendingTrade): string {
  const base =
    `🪙 *${t.safeDisplayTicker ?? t.symbol}* — ${t.name}\n` +
    `⛓ Chain: ${t.chain}\n` +
    `💰 Price: $${formatPrice(t.price)}\n` +
    `📈 MCap: ${t.marketCap > 0 ? formatNum(t.marketCap) : "—"}\n` +
    `💧 Liq: ${formatNum(t.liquidity)}\n` +
    `📊 Vol 24h: ${formatNum(t.volume24h)}`;

  if (!t.timeframe) return base + `\n\nPick a timeframe:`;
  if (!t.side)      return base + `\n\n⏱ ${t.timeframe} — Long or Short?`;
  const sideLabel   = t.side === "long" ? "📈 Long" : "📉 Short";
  // Amount not chosen yet (undefined, or -1 = awaiting custom input) → ask it.
  // Once set, show the chosen stake — the caller appends "💬 Say something!"
  // for the tagline step. Without this the tagline card still said
  // "— How much?", making it look like a second amount prompt. Marcos 2026-05-25.
  if (!t.amount || t.amount <= 0) return base + `\n\n⏱ ${t.timeframe} · ${sideLabel} — How much?`;
  return base + `\n\n⏱ ${t.timeframe} · ${sideLabel} · $${t.amount}`;
}

async function marketCard(m: any): Promise<string> {
  const longPool  = parseFloat(m.long_pool);
  const shortPool = parseFloat(m.short_pool);
  const total     = longPool + shortPool;
  const longPct   = total > 0 ? Math.round(longPool  / total * 100) : 50;
  const shortPct  = 100 - longPct;
  const closes    = new Date(m.closes_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  // V5.4: per-market fee snapshot (legacy markets fee_bps NULL → 5%).
  const feeKeep   = 1 - marketFeeBps(m.fee_bps) / 10_000;
  const longMult  = longPool  > 0 ? (1 + shortPool * feeKeep / longPool).toFixed(2)  + "x" : "—";
  const shortMult = shortPool > 0 ? (1 + longPool  * feeKeep / shortPool).toFixed(2) + "x" : "—";
  // Resolve the safe ticker from (symbol, ca, chain). Prefer a display_ticker
  // already on the row (e.g. from GET /markets); else re-derive so an impostor
  // CA never shows a clean canonical ticker in the Telegram card.
  const ticker = m.display_ticker
    ?? (await resolveSafeDisplayTicker({ symbol: m.symbol, ca: m.ca ?? null, chain: m.chain })).displayTicker;
  return (
    `🔥 *${ticker}* · ${m.timeframe} · ${m.chain}\n` +
    `💰 Entry: $${formatPrice(parseFloat(m.entry_price))}\n` +
    `⏰ Closes: ${closes}\n\n` +
    `🏊 Total pool: $${total.toFixed(0)}\n` +
    `  📈 Long: $${longPool.toFixed(0)} (${longPct}%) → ${longMult}\n` +
    `  📉 Short: $${shortPool.toFixed(0)} (${shortPct}%) → ${shortMult}`
  );
}

// V5 pending-market card + "take the other side" button. Replaces the
// legacy V4 marketSide/marketAmt keyboards (bet-any-side-any-amount on a
// live pool). In V5 a pending market has only the OPENER's side; taking it
// means taking the OPPOSITE side at the opener's stake (one tap). The take
// autosigns via tryAutosignLazyTake. Marcos 2026-05-25.
async function pendingCard(p: any): Promise<string> {
  const openerSide = p.side === "long" ? "LONG 📈" : "SHORT 📉";
  const amount = parseFloat(p.amount);
  const closes = new Date(p.closes_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  const tag = p.tagline ? `\n💬 "${p.tagline}"` : "";
  const by  = p.opener_username ? ` by @${p.opener_username}` : "";
  const ticker = p.display_ticker
    ?? (await resolveSafeDisplayTicker({ symbol: p.symbol, ca: p.ca ?? null, chain: p.chain })).displayTicker;
  return (
    `🔥 *${ticker}* · ${p.timeframe} · ${p.chain}\n` +
    `💰 Entry: $${formatPrice(parseFloat(p.entry_price))}\n` +
    `⏰ Closes: ${closes}\n\n` +
    `Opener is *${openerSide}* for *$${amount.toFixed(0)}*${by}${tag}`
  );
}

function takeOtherSideKeyboard(pendingId: string, openerSide: string) {
  const otherSide = openerSide === "long" ? "SHORT 📉" : "LONG 📈";
  return Markup.inlineKeyboard([[
    Markup.button.callback(`⚔️ Take the other side (${otherSide})`, `marketake:${pendingId}`),
  ]]);
}

// Side + amount picker for betting on an EXISTING live V5 market (queue-bet
// via placeBetsBatch). marketqside → marketqamt → tryAutosignQueuedBet. This
// is the V5 equivalent of the old V4 marketside/marketamt flow (same UX as
// the web: pick side + amount on a live market). Marcos 2026-05-25.
function liveMarketSideKeyboard(marketId: string) {
  return Markup.inlineKeyboard([[
    Markup.button.callback("📈 LONG", `marketqside:${marketId}:long`),
    Markup.button.callback("📉 SHORT", `marketqside:${marketId}:short`),
  ]]);
}

function liveMarketAmtKeyboard(marketId: string, side: string, tgId: number) {
  const presets = getPresets(tgId);
  return Markup.inlineKeyboard([
    presets.map(a => Markup.button.callback(`$${a}`, `marketqamt:${marketId}:${side}:${a}`)),
    [Markup.button.callback("↩️ Back", `marketqback:${marketId}`)],
  ]);
}

function tfKeyboard(tgId: number) {
  return Markup.inlineKeyboard([
    TIMEFRAMES.map(tf => Markup.button.callback(tf, `tf:${tgId}:${tf}`)),
  ]);
}

function sideKeyboard(tgId: number) {
  return Markup.inlineKeyboard([
    [
      Markup.button.callback("📈 LONG",  `side:${tgId}:long`),
      Markup.button.callback("📉 SHORT", `side:${tgId}:short`),
    ],
    [Markup.button.callback("↩️ Change TF", `changetf:${tgId}`)],
  ]);
}

function amtKeyboard(tgId: number) {
  const presets = getPresets(tgId);
  return Markup.inlineKeyboard([
    presets.map(a => Markup.button.callback(`$${a}`, `amt:${tgId}:${a}`)),
    [
      Markup.button.callback("✏️ Custom", `amtcustom:${tgId}`),
      Markup.button.callback("↩️ Change side", `changeside:${tgId}`),
    ],
  ]);
}

// ─── Bot ──────────────────────────────────────────────────────────────────────

export async function startBot() {
  console.log("[bot] startBot() called — BOT_TOKEN present:", !!BOT_TOKEN);
  if (!BOT_TOKEN) {
    console.warn("⚠️  BOT_TOKEN not set — Telegram bot disabled");
    return;
  }

  const bot = new Telegraf(BOT_TOKEN);

  // Bot username (fetched once at startup for deep links)
  let botUsername = "FUDmarkets_BOT";
  bot.telegram.getMe().then(me => { botUsername = me.username ?? botUsername; }).catch(() => {});

  // DEBUG: log every update
  bot.use((ctx, next) => {
    const type = (ctx.update as any).message?.text ? "text" : Object.keys(ctx.update)[1] ?? "?";
    const text = (ctx.update as any).message?.text ?? "";
    console.log(`[bot:update] type=${type} text="${text.slice(0, 40)}"`);
    return next();
  });

  // /start
  bot.start(async (ctx) => {
    const payload = (ctx as any).startPayload as string | undefined;

    // Frontend-initiated link: start=link_{token}
    if (payload?.startsWith("link_")) {
      const linkToken = payload.slice("link_".length);
      const { rows: [entry] } = await db.query(
        `DELETE FROM tg_link_tokens WHERE token = $1 AND expires_at > NOW() AND user_id IS NOT NULL RETURNING user_id`,
        [linkToken]
      ).catch(() => ({ rows: [] }));
      if (!entry) {
        return ctx.reply("❌ Link expired or invalid. Try again from the app.");
      }
      await db.query(`UPDATE users SET telegram_id = NULL, telegram_username = NULL WHERE telegram_id = $1 AND id != $2`, [ctx.from.id, entry.user_id]);
      await db.query(`UPDATE users SET telegram_id = $1, telegram_username = $2 WHERE id = $3`, [ctx.from.id, ctx.from.username ?? null, entry.user_id]);
      sessions.delete(ctx.from.id);
      const { rows: [user] } = await db.query(`SELECT username FROM users WHERE id = $1`, [entry.user_id]);
      return ctx.reply(`✅ Telegram connected to *${user?.username ?? "your account"}*!\n\nYou can now trade directly from here.`, { parse_mode: "Markdown" });
    }

    // Accept Challenge deep link: start=challenge_{marketId} → redirect to web
    if (payload?.startsWith("challenge_")) {
      const marketId = payload.slice("challenge_".length);
      const { rows: [market] } = await db.query(`SELECT * FROM markets WHERE id = $1`, [marketId]).catch(() => ({ rows: [] }));
      if (market) {
        const tradeUrl = `${FRONTEND_URL}/market/${marketId}`;
        return ctx.reply(
          await marketCard(market),
          {
            parse_mode: "Markdown",
            ...Markup.inlineKeyboard([[
              Markup.button.url("🔥 Trade on FUD.markets →", tradeUrl),
            ]]),
          }
        );
      }
    }

    // Take the other side, deep-linked from a group challenge card:
    // start=take_{pendingId}. Opens the private chat and shows the pending
    // market with the in-DM "Take the other side" button so the user places
    // the bet from here (not silently in the group). Marcos 2026-05-25.
    if (payload?.startsWith("take_")) {
      const pendingId = payload.slice("take_".length);
      const { rows: [p] } = await db.query(
        `SELECT pm.id, pm.symbol, pm.ca, pm.chain, pm.timeframe, pm.side, pm.amount,
                pm.entry_price, pm.closes_at, pm.tagline, pm.status, pm.expires_at,
                u.username AS opener_username
           FROM pending_markets pm
           JOIN users u ON u.id = pm.opener_user_id
          WHERE pm.id = $1`,
        [pendingId],
      ).catch(() => ({ rows: [] as any[] }));
      if (!p) return ctx.reply("That challenge is no longer available.");
      if (p.status !== "pending" || new Date(p.expires_at) <= new Date() || new Date(p.closes_at) <= new Date()) {
        return ctx.reply("That challenge is no longer open to take.");
      }
      const session = await getSession(ctx.from.id);
      if (!session) {
        return ctx.reply(
          "🔗 Link your Telegram first to take this — open fud.markets → Settings → connect Telegram, then tap the button again.",
        );
      }
      return ctx.reply(await pendingCard(p), {
        parse_mode: "Markdown",
        ...takeOtherSideKeyboard(p.id, p.side),
      });
    }

    // Deep-links from the DM-only gate on /markets and /challenges run in a
    // group — they bring the user here (private chat) to place safely.
    if (payload === "markets")    return sendLiveMarkets(ctx);
    if (payload === "challenges") return sendChallenges(ctx);

    const session = await getSession(ctx.from.id);
    if (session) {
      // If there's a pending trade from a group, jump straight into the flow
      const pending = pendingTrades.get(ctx.from.id);
      if (pending && !pending.timeframe) {
        return ctx.reply(tokenMessage(pending), { parse_mode: "Markdown", ...tfKeyboard(ctx.from.id) });
      }
      await ctx.reply(
        `👋 Welcome back, *${session.username}*!\n\n` +
          `Paste a contract address to discover a token\n` +
          `/search <CA>\n` +
          `/markets — open markets\n` +
          `/me — your account\n\n` +
          `_Enable Autosign in your FUD settings to trade from Telegram_`,
        { parse_mode: "Markdown" }
      );
    } else {
      // Generate a one-time link token (expires in 10 min), stored in DB
      const token = randomBytes(16).toString("hex");
      try {
        console.log(`[bot:/start] Inserting tg_link token for tgId=${ctx.from.id}, token=${token.slice(0, 8)}…`);
        await db.query(
          `INSERT INTO tg_link_tokens (token, tg_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
           ON CONFLICT (token) DO UPDATE SET tg_id = $2, expires_at = NOW() + INTERVAL '10 minutes'`,
          [token, ctx.from.id]
        );
        console.log(`[bot:/start] Token inserted OK`);
      } catch (e: any) {
        console.error(`[bot:/start] DB insert failed:`, e.message);
        return ctx.reply("Internal error — please try again in a moment.");
      }

      const linkUrl = `${FRONTEND_URL}?tg_link=${token}`;
      await ctx.reply(
        `👋 *FUD\\.markets*\n\n` +
          `Your Telegram is not linked to any account\\.\n\n` +
          `Tap the button below to register or sign in and connect automatically\\.`,
        {
          parse_mode: "MarkdownV2",
          ...Markup.inlineKeyboard([[
            Markup.button.url("🌐 Register / Sign up", linkUrl),
          ]]),
        }
      );
    }
  });

  // /search <CA> — CA-only. Tickers map to the wrong token on DexScreener,
  // so we require the contract address (Marcos 2026-05-13).
  bot.command("search", async (ctx) => {
    const query = ctx.message.text.replace(/^\/search\s*/i, "").trim();
    if (!query) return ctx.reply("Usage: /search <contract address>\nPaste a CA (0x… for EVM, base58 for Solana). Tickers aren't accepted — they pick the wrong token.");
    if (!looksLikeCA(query)) {
      return ctx.reply(`❌ "${query.slice(0, 20)}" doesn't look like a contract address. Paste the CA — 0x… for EVM or base58 for Solana.`);
    }

    const isGroup = ctx.chat.type !== "private";
    const msg = await ctx.reply("🔍 Searching…");
    let token: PendingTrade | null;
    try {
      token = await searchToken(query);
    } catch {
      await ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});
      return ctx.reply("❌ Error searching for token.");
    }
    await ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});

    if (!token) return ctx.reply(`❌ CA "${query.slice(0, 20)}…" not found on DexScreener.`);

    if (isGroup) {
      // Store group chatId so the market card gets posted back here after opening
      token.groupChatId = ctx.chat.id;
      pendingTrades.set(ctx.from.id, token);
      // Post token card in group with "Open Trade" deep-link button
      const deepLink = `https://t.me/${botUsername}?start=opentrade`;
      await ctx.reply(groupTokenMessage(token), {
        parse_mode: "Markdown",
        ...Markup.inlineKeyboard([[Markup.button.url("🔥 Open Trade", deepLink)]]),
      });
    } else {
      pendingTrades.set(ctx.from.id, token);
      await ctx.reply(tokenMessage(token), { parse_mode: "Markdown", ...tfKeyboard(ctx.from.id) });
    }
  });

  // Any text message that looks like a CA or short symbol (auto-detect)
  bot.on(message("text"), async (ctx, next) => {
    const text = ctx.message.text.trim();

    // Let command handlers deal with commands
    if (text.startsWith("/")) return next();

    // ── X agent edit mode ──────────────────────────────────────────────────
    if (pendingXEdits.has(ctx.from.id)) {
      const { callbackId } = pendingXEdits.get(ctx.from.id)!;
      const customReply = text.slice(0, 270);
      pendingXEdits.set(ctx.from.id, { callbackId, customReply });
      await ctx.reply(
        `*Preview* (${customReply.length}/270):\n\n_${customReply}_`,
        {
          parse_mode: "Markdown",
          ...Markup.inlineKeyboard([[
            Markup.button.callback("✅ Post this", `xconfirm_${callbackId}`),
            Markup.button.callback("❌ Cancel",    `xcancel_${callbackId}`),
          ]]),
        }
      );
      return;
    }

    // In groups: respond to CAs (token search) or @mentions (AI)
    if (ctx.chat.type !== "private") {
      const isCA = looksLikeCA(text);

      // CA pasted → search token and post card
      if (isCA) {
        const searching = await ctx.reply("🔍 Searching…");
        try {
          const found = await searchToken(text);
          await ctx.telegram.deleteMessage(ctx.chat.id, searching.message_id).catch(() => {});
          if (!found) return ctx.reply(`❌ Token not found for that CA.`);
          found.groupChatId = ctx.chat.id;
          pendingTrades.set(ctx.from.id, found);
          const deepLink = `https://t.me/${botUsername}?start=opentrade`;
          await ctx.reply(groupTokenMessage(found), {
            parse_mode: "Markdown",
            ...Markup.inlineKeyboard([[Markup.button.url("🔥 Open Trade", deepLink)]]),
          });
        } catch {
          await ctx.telegram.deleteMessage(ctx.chat.id, searching.message_id).catch(() => {});
          await ctx.reply("❌ Error searching token.");
        }
        return;
      }

      // Only explicit @FUDmarkets_BOT or a reply to the bot triggers
      // an AI response in groups. Name variants like "fudbot" / "fuddy"
      // used to trigger too, but that was noisy in group chats — matched
      // casual talk about the project. Mirrors how the X bot only reacts
      // to @FUDmarkets, never to "fud" mentions in the body.
      const mentionRegex = new RegExp(`@${botUsername}\\b`, "i");
      const isRepliedTo  = (ctx.message as any).reply_to_message?.from?.username?.toLowerCase() === botUsername.toLowerCase();
      const isMentioned  = mentionRegex.test(text) || isRepliedTo;

      if (!isMentioned) return;

      const cleanText = text.replace(mentionRegex, "").trim() || "gm";
      if (!anthropic) return ctx.reply("gm ser 🫡");
      try {
        const session = await getSession(ctx.from.id).catch(() => null);
        const reply = await getAIReply(ctx.from.id, cleanText, session);
        await ctx.reply(reply, { parse_mode: "Markdown" });
      } catch (e: any) {
        console.error("[bot] AI group error:", e.message);
      }
      return;
    }

    // Require account for trading
    const session = await getSession(ctx.from.id);
    if (!session) {
      return ctx.reply(
        `🔗 *Link your Telegram first\\!*\n\nCreate your account at [fud\\.markets](${FRONTEND_URL}) or use /start to register here\\.`,
        { parse_mode: "MarkdownV2" }
      );
    }

    // Custom amount for new market flow (amount === -1 means waiting for custom input)
    const pendingForCustomAmt = pendingTrades.get(ctx.from.id);
    if (pendingForCustomAmt?.amount === -1 && pendingForCustomAmt.side && !pendingForCustomAmt.awaitingMsg) {
      const amount = parseFloat(text.replace(",", "."));
      if (isNaN(amount) || amount <= 0) {
        return ctx.reply("❌ Invalid amount. Enter a number, e.g. 37.5");
      }
      pendingForCustomAmt.amount = amount;
      pendingForCustomAmt.awaitingMsg = true;
      pendingTrades.set(ctx.from.id, pendingForCustomAmt);
      await ctx.reply(
        tokenMessage(pendingForCustomAmt) + `\n\n✅ Amount set: *$${pendingForCustomAmt.amount}*\n💬 *Add a message?* (optional) — type it, or tap Skip to open now.`,
        { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🚫 No message — open now", `skipmsg:${ctx.from.id}`)]]) }
      );
      return;
    }

    // If user is writing a message/challenge for a pending trade, capture it
    const pendingForMsg = pendingTrades.get(ctx.from.id);
    if (pendingForMsg?.awaitingMsg) {
      pendingForMsg.awaitingMsg = false;
      pendingTrades.set(ctx.from.id, pendingForMsg);
      await createMarketAndHandoff(ctx, ctx.from.id, text);
      return;
    }

    // CA-only fast path. Marcos 2026-05-13: tickers like PEPE/BTC/WIF
    // collapse onto the wrong DexScreener match, so the previous
    // all-uppercase shortcut was removed. Anything that isn't a CA
    // gets routed through the AI agent, which has its own CA-only
    // gate (it tells the user to send a CA instead of guessing).
    if (looksLikeCA(text)) {
      console.log(`[bot] Searching token by CA: "${text}"`);
      const msg = await ctx.reply("🔍 Searching…");
      try {
        const token = await searchToken(text);
        await ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});
        if (!token) {
          return ctx.reply(`❌ CA "${text.slice(0, 20)}…" not found on DexScreener.`);
        }
        // Pre-gate the entire interactive flow on autosign consent —
        // no point letting the user pick a timeframe + amount + tagline
        // if we're going to reject at the end (Codex 2026-05-13).
        if (session) {
          const gate = await checkAutosignGate(session.userId);
          if (!gate.ok) {
            if (gate.reason === "feature_disabled") {
              return ctx.reply(`Autosign is temporarily paused for maintenance. Try again in a few minutes.`);
            }
            return ctx.reply(
              `Hey @${session.username}, enable Autosign in your fud.markets settings to trade from here.`,
              { ...Markup.inlineKeyboard([[Markup.button.url("Open FUD.markets →", FRONTEND_URL)]]) },
            );
          }
        }
        pendingTrades.set(ctx.from.id, token);
        await ctx.reply(tokenMessage(token), { parse_mode: "Markdown", ...tfKeyboard(ctx.from.id) });
      } catch (e: any) {
        console.error("[bot] searchToken error:", e.message);
        await ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});
        await ctx.reply(`❌ Error searching token: ${e.message}`);
      }
      return;
    }

    // Everything else → AI agent
    if (!anthropic) return;
    try {
      const reply = await getAIReply(ctx.from.id, text, session);
      await ctx.reply(reply, { parse_mode: "Markdown" });
    } catch (e: any) {
      console.error("[bot] AI error:", e.message);
    }
  });

  // Timeframe selected → show Long/Short buttons
  bot.action(/^tf:(\d+):(.+)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    const tf   = ctx.match[2];

    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");

    const trade = pendingTrades.get(tgId);
    if (!trade) return ctx.answerCbQuery("Session expired. Search the token again.");

    trade.timeframe = tf;
    trade.side = undefined;
    pendingTrades.set(tgId, trade);

    await ctx.editMessageText(tokenMessage(trade), { parse_mode: "Markdown", ...sideKeyboard(tgId) });
    await ctx.answerCbQuery();
  });

  // Change TF (back to timeframe selection)
  bot.action(/^changetf:(\d+)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");

    const trade = pendingTrades.get(tgId);
    if (!trade) return ctx.answerCbQuery("Session expired.");

    trade.timeframe = undefined;
    trade.side = undefined;
    pendingTrades.set(tgId, trade);
    await ctx.editMessageText(tokenMessage(trade), { parse_mode: "Markdown", ...tfKeyboard(tgId) });
    await ctx.answerCbQuery();
  });

  // Side selected (Long / Short) → show amount buttons
  bot.action(/^side:(\d+):(long|short)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    const side = ctx.match[2];

    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");

    const trade = pendingTrades.get(tgId);
    if (!trade || !trade.timeframe) return ctx.answerCbQuery("Session expired.");

    trade.side = side;
    pendingTrades.set(tgId, trade);

    await ctx.editMessageText(tokenMessage(trade), { parse_mode: "Markdown", ...amtKeyboard(tgId) });
    await ctx.answerCbQuery();
  });

  // Change side (back to Long/Short selection)
  bot.action(/^changeside:(\d+)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");

    const trade = pendingTrades.get(tgId);
    if (!trade) return ctx.answerCbQuery("Session expired.");

    trade.side = undefined;
    pendingTrades.set(tgId, trade);
    await ctx.editMessageText(tokenMessage(trade), { parse_mode: "Markdown", ...sideKeyboard(tgId) });
    await ctx.answerCbQuery();
  });

  // Amount selected → ask for optional message
  bot.action(/^amt:(\d+):(\d+)$/, async (ctx) => {
    const tgId   = parseInt(ctx.match[1]);
    const amount = parseFloat(ctx.match[2]);

    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");

    const trade = pendingTrades.get(tgId);
    if (!trade || !trade.timeframe || !trade.side) {
      return ctx.answerCbQuery("Session expired. Search the token again.");
    }

    trade.amount = amount;
    trade.awaitingMsg = true;
    pendingTrades.set(tgId, trade);

    await ctx.editMessageText(
      tokenMessage(trade) + `\n\n✅ Amount set: *$${trade.amount}*\n💬 *Add a message?* (optional) — type it, or tap Skip to open now.`,
      {
        parse_mode: "Markdown",
        ...Markup.inlineKeyboard([[Markup.button.callback("🚫 No message — open now", `skipmsg:${tgId}`)]]),
      }
    );
    trade.flowMsgId = ctx.callbackQuery.message?.message_id;
    pendingTrades.set(tgId, trade);
    await ctx.answerCbQuery();
  });

  // Skip message → place bet immediately
  bot.action(/^skipmsg:(\d+)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");
    await ctx.answerCbQuery("⏳ Opening market…");
    await createMarketAndHandoff(ctx, tgId, "");
  });

  // Custom amount for new market flow
  bot.action(/^amtcustom:(\d+)$/, async (ctx) => {
    const tgId = parseInt(ctx.match[1]);
    if (tgId !== ctx.from.id) return ctx.answerCbQuery("Not yours.");
    const trade = pendingTrades.get(tgId);
    if (!trade || !trade.side) return ctx.answerCbQuery("Session expired.");
    trade.awaitingMsg = false;
    trade.amount = -1; // flag: awaiting custom amount
    pendingTrades.set(tgId, trade);
    await ctx.answerCbQuery();
    await ctx.reply("✏️ Enter the amount to bet (e.g. 37.5):");
  });

  // ─── Helper: open market + generate web deep link ────────────────────────────
  async function createMarketAndHandoff(ctx: any, tgId: number, tagline: string) {
    const trade = pendingTrades.get(tgId);
    if (!trade || !trade.timeframe || !trade.side || !trade.amount) return;

    const session = await getSession(tgId);
    if (!session) {
      await ctx.reply("🔗 Link your Telegram first. Use /start.");
      return;
    }

    // Autosign-only gate — Marcos 2026-05-13: TG mirrors X. No manual
    // sign fallback. If the user hasn't enabled autosign, we never
    // touch the chain (no orphan markets) and tell them what to do.
    const gate = await checkAutosignGate(session.userId);
    if (!gate.ok) {
      if (gate.reason === "feature_disabled") {
        await ctx.reply(`Autosign is temporarily paused for maintenance. Try again in a few minutes.`);
      } else {
        await ctx.reply(
          `Hey @${session.username}, enable Autosign in your fud.markets settings to trade from here.`,
          { ...Markup.inlineKeyboard([[Markup.button.url("Open FUD.markets →", FRONTEND_URL)]]) },
        );
      }
      pendingTrades.delete(tgId);
      return;
    }

    // Rate limit antes de cualquier work — protege backend de abuso.
    const rl = checkMarketCreationRateLimit(session.userId);
    if (!rl.ok) {
      if (rl.reason === "cooldown") {
        await ctx.reply(`⏱ Slow down — try again in ${rl.retryInSec}s.`);
      } else {
        await ctx.reply(`🚫 Daily market creation cap reached. Come back tomorrow.`);
      }
      return;
    }

    // Gate 2 (Codex P2): pre-check vault balance ANTES de crear el
    // market y handoff. Si no llega al amount, no creamos market
    // huérfano + mandamos al user a depositar en vez de a un confirm
    // flow que va a fallar al firmar.
    const balanceCheck = await checkVaultBalanceV5(session.userId);
    if (!balanceCheck.ok) {
      if (balanceCheck.reason === "no_wallet") {
        await ctx.reply(
          `Hey @${session.username}, your wallet setup isn't complete yet. Head to Settings → Autosign on fud.markets to finish setup.`,
          {
            ...Markup.inlineKeyboard([[Markup.button.url("Complete setup →", `${FRONTEND_URL}?settings=autosign`)]]),
          },
        );
        return;
      }
      // rpc_error → soft-fail, dejamos pasar y que falle en web si pasa
      console.warn("[bot] vault balance rpc_error for user", session.userId);
    } else if (balanceCheck.vault < trade.amount) {
      const short = (trade.amount - balanceCheck.vault).toFixed(2);
      await ctx.reply(
        `💸 *Not enough USDC in your vault*\n\nYou need *$${trade.amount}* but only have *$${balanceCheck.vault.toFixed(2)}*. Deposit *$${short}* more first.`,
        {
          parse_mode: "Markdown",
          ...Markup.inlineKeyboard([[Markup.button.url("Deposit on FUD.markets →", `${FRONTEND_URL}?deposit=1`)]]),
        },
      );
      return;
    }

    // Banned-token guard — parity with the legacy /markets check.
    if (await isTokenBanned(trade.ca, trade.chain)) {
      await ctx.reply(`🚫 That token is banned from FUD.markets.`);
      pendingTrades.delete(tgId);
      return;
    }

    const emoji  = trade.side === "long" ? "📈" : "📉";
    const chatId = ctx.chat?.id ?? ctx.callbackQuery?.message?.chat?.id;

    // Snapshot entry market cap from the CA (chain-aware) for settlement
    // thresholds — parity with the web client. null is fine (small-cap
    // default); canonical majors get the big-cap sentinel inside autosign.
    const meta = await resolveTokenMetaFromCA(trade.ca, trade.chain);

    // V5 lazy open: sign the LazyBet intent (Privy) + persist the pending
    // market via the shared core. Replaces the legacy eager create + V4
    // placeBet. V5 open is binary — success means a pending market exists
    // waiting for a taker; any failure means nothing was created.
    const auto = await tryAutosignLazyMarket({
      userId:    session.userId,
      username:  session.username,
      symbol:    trade.symbol,
      chain:     trade.chain,
      ca:        trade.ca,
      timeframe: trade.timeframe as Timeframe,
      side:      trade.side as "long" | "short",
      amount:    trade.amount,
      tagline:   tagline || null,
      entryMarketCap: meta?.marketCap ?? null,
    });

    if (!auto.ok) {
      pendingTrades.delete(tgId);
      // DM bot → an explicit reply is expected (unlike X, where failure is
      // silent). Map the skip to a clear reason.
      const text =
        auto.skip === "hard_cap"            ? `❌ Trade exceeds maximum allowed.` :
        auto.skip === "no_balance"          ? `💸 Not enough USDC in your vault${auto.detail ? `: ${auto.detail}` : "."}` :
        auto.skip === "no_wallet"           ? `Wallet not set up yet — finish setup on fud.markets first.` :
        auto.skip === "no_consent" ||
        auto.skip === "consent_revoked" ||
        auto.skip === "no_privy_delegation" ? `Hey @${session.username}, enable Autosign in your fud.markets settings to trade from here.` :
        auto.skip === "feature_disabled"    ? `Autosign is temporarily paused for maintenance. Try again in a few minutes.` :
        `❌ Couldn't open the market${auto.detail ? `: ${auto.detail}` : "."}`;
      if (trade.flowMsgId && chatId) {
        await ctx.telegram.editMessageText(chatId, trade.flowMsgId, undefined, text, { parse_mode: "Markdown" }).catch(() => {});
      } else {
        await ctx.reply(text, { parse_mode: "Markdown" });
      }
      return;
    }

    recordMarketCreation(session.userId);
    pendingTrades.delete(tgId);

    // "Opened" = intent signed + published; the market is waiting for a
    // taker (never claim it's matched). Link resolves via the pending
    // fallback in GET /markets/:id.
    const okText =
      `${emoji} *${trade.side.toUpperCase()} $${trade.amount}* on *${trade.safeDisplayTicker ?? trade.symbol}* · ${trade.timeframe} — *Opened* ✅\n` +
      `💰 Entry: $${formatPrice(auto.entryPrice)}\n` +
      `⚔️ Waiting for someone to take the other side.\n` +
      `🔗 [View market](${FRONTEND_URL}/market/${auto.pendingMarketId})`;
    if (trade.flowMsgId && chatId) {
      await ctx.telegram.editMessageText(chatId, trade.flowMsgId, undefined, okText, { parse_mode: "Markdown" }).catch(() => {});
    } else {
      await ctx.reply(okText, { parse_mode: "Markdown" });
    }

    // Post challenge card to group (or DM if no group). Always has a real
    // pending position now (failures returned above).
    const targetChatId = trade.groupChatId ?? chatId;
    if (targetChatId && targetChatId !== chatId) {
      const quote    = tagline.trim() || "Let's ride! 🔥";
      const sideText = trade.side === "long" ? "LONG 📈" : "SHORT 📉";
      const challengeText =
        `"${quote}"\n\n` +
        `@${session.username} is going *${sideText}* for *$${trade.amount}*\n` +
        `🪙 *${trade.safeDisplayTicker ?? trade.symbol}* · ${trade.timeframe}\n` +
        `💰 Entry: $${formatPrice(auto.entryPrice)}`;

      const chainSlug  = ({
        SOL: "solana", BASE: "base", ETH: "ethereum", BSC: "bsc", TRON: "tron",
        SUI: "sui", MONAD: "monad", POLYGON: "polygon", AVAX: "avalanche",
        PULSECHAIN: "pulsechain", TON: "ton", ABSTRACT: "abstract", HYPEREVM: "hyperevm", HOOD: "robinhood",
      } as Record<string, string>)[trade.chain] ?? trade.chain.toLowerCase();
      const chartUrl   = `https://dexscreener.com/${chainSlug}/${trade.ca}`;
      // "Take the other side" deep-links into the PRIVATE chat with the bot
      // (start=take_{pendingId}) where the user places the bet — group buttons
      // can't safely autosign, and a callback in the group would either fire
      // silently or wipe the shared card on failure. Marcos 2026-05-25: must
      // open the DM and let you place from there (not a dead web link).
      const takeDeepLink = `https://t.me/${botUsername}?start=take_${auto.pendingMarketId}`;
      await ctx.telegram.sendMessage(targetChatId, challengeText, {
        parse_mode: "Markdown",
        ...Markup.inlineKeyboard([[
          Markup.button.url("⚔️ Take the other side", takeDeepLink),
          Markup.button.url("📊 Chart", chartUrl),
        ]]),
      });
    }
  }

  // Placement (take / queue-bet) is DM-ONLY — the buttons autosign real-money
  // actions, and a group callback would fire silently or edit a shared card.
  // Group invocations of /markets and /challenges get a deep-link into the
  // bot DM (start=markets|challenges) instead. Codex P2 2026-05-25.
  function dmOnlyGate(ctx: any, payload: string): boolean {
    if (ctx.chat?.type === "private") return false;
    ctx.reply("Trading happens in our private chat (real-money actions). Tap to open 👇", {
      ...Markup.inlineKeyboard([[Markup.button.url("Open bot →", `https://t.me/${botUsername}?start=${payload}`)]]),
    }).catch(() => {});
    return true;
  }

  // List LIVE V5 markets (matched, accepting more bets) → side+amount picker →
  // queue-bet. Strictly V5 + on-chain + open + env-matched: we query `markets`
  // directly (not the GET /markets feed, which mixes pendings disguised as
  // open) so a challenge never shows up as a live market.
  async function sendLiveMarkets(ctx: any) {
    const { rows: live } = await db.query(
      `SELECT id, symbol, ca, chain, timeframe, entry_price, closes_at, long_pool, short_pool
         FROM markets
        WHERE status = 'open' AND vault_version = 'v5'
          AND onchain_market_id IS NOT NULL AND env = $1
          AND closes_at > NOW()
        ORDER BY created_at DESC
        LIMIT 5`,
      [LAZY_ENV],
    ).catch(() => ({ rows: [] as any[] }));
    if (live.length === 0) {
      return ctx.reply("No live markets right now. Try /challenges to take the other side of an open challenge.");
    }
    for (const m of live) {
      await ctx.reply(await marketCard(m), { parse_mode: "Markdown", ...liveMarketSideKeyboard(m.id) });
    }
  }

  // List open PENDING lazy markets (waiting for a taker) → "take the other
  // side" (autosigns the OPPOSITE side at the opener's stake, one tap).
  async function sendChallenges(ctx: any) {
    const { rows: pendings } = await db.query(
      `SELECT pm.id, pm.symbol, pm.ca, pm.chain, pm.timeframe, pm.side, pm.amount,
              pm.entry_price, pm.closes_at, pm.tagline, u.username AS opener_username
         FROM pending_markets pm
         JOIN users u ON u.id = pm.opener_user_id
        WHERE pm.status = 'pending' AND pm.env = $1
          AND LEAST(pm.expires_at, pm.closes_at) > NOW()
        ORDER BY pm.created_at DESC
        LIMIT 5`,
      [LAZY_ENV],
    ).catch(() => ({ rows: [] as any[] }));
    if (pendings.length === 0) return ctx.reply("No open challenges waiting for a taker right now.");
    for (const p of pendings) {
      await ctx.reply(await pendingCard(p), { parse_mode: "Markdown", ...takeOtherSideKeyboard(p.id, p.side) });
    }
  }

  bot.command("markets", async (ctx) => {
    if (dmOnlyGate(ctx, "markets")) return;
    await sendLiveMarkets(ctx);
  });

  bot.command("challenges", async (ctx) => {
    if (dmOnlyGate(ctx, "challenges")) return;
    await sendChallenges(ctx);
  });

  // Take the other side of a pending market → autosign the OPPOSITE side at
  // the opener's stake via the V5 take flow. One tap, no side/amount picker:
  // side is forced opposite, amount defaults to the opener's. DM bot, so we
  // reply with the outcome either way.
  bot.action(/^marketake:(.+)$/, async (ctx) => {
    const [, pendingId] = ctx.match;
    // Placement is DM-only — never autosign from a group callback (Codex P2).
    if (ctx.chat?.type !== "private") {
      return ctx.answerCbQuery("Open me in a private chat to take this.", { show_alert: true });
    }
    await ctx.answerCbQuery();

    const session = await getSession(ctx.from.id);
    if (!session) { await ctx.reply("🔗 Link your Telegram first. Use /start."); return; }

    const auto = await tryAutosignLazyTake({
      userId:   session.userId,
      username: session.username,
      pendingId,
    });

    if (auto.ok) {
      const emoji = auto.takerSide === "long" ? "📈" : "📉";
      const takenTicker = (await resolveSafeDisplayTicker({ symbol: auto.symbol, ca: auto.ca, chain: auto.chain })).displayTicker;
      await ctx.editMessageText(
        `${emoji} *${auto.takerSide.toUpperCase()} $${auto.amount}* on *${takenTicker}* — *Taken* ✅\n` +
        `⚙️ Matching on-chain now — confirmation in ~30s.\n` +
        `🔗 [View market](${FRONTEND_URL}/market/${auto.pendingMarketId})`,
        { parse_mode: "Markdown" },
      ).catch(() => {});
      return;
    }

    console.warn(`[bot] lazy take skip — userId=${session.userId} pending=${pendingId} skip=${auto.skip} detail="${auto.detail ?? ""}"`);
    const text =
      auto.skip === "take_unavailable"    ? (
        auto.detail === "own_market" ? `You can't take your own challenge — that's your side.` :
        auto.detail === "expired"    ? `This challenge has expired (closed before a taker matched).` :
        `This challenge was already matched (or is no longer open).`
      ) :
      auto.skip === "hard_cap"            ? `Trade exceeds maximum allowed.` :
      auto.skip === "no_balance"          ? `💸 Not enough USDC in your vault${auto.detail ? `: ${auto.detail}` : "."}` :
      auto.skip === "no_wallet"           ? `Wallet not set up yet — finish setup on fud.markets first.` :
      auto.skip === "no_consent" ||
      auto.skip === "consent_revoked" ||
      auto.skip === "no_privy_delegation" ? `Hey @${session.username}, enable Autosign in your fud.markets settings to trade from here.` :
      auto.skip === "feature_disabled"    ? `Autosign is temporarily paused for maintenance. Try again in a few minutes.` :
      `❌ Couldn't take the market${auto.detail ? `: ${auto.detail}` : "."}`;
    await ctx.editMessageText(text, { parse_mode: "Markdown" }).catch(() => {});
  });

  // Queue-bet on a LIVE market: side selected → show amount keyboard.
  bot.action(/^marketqside:(.+):(long|short)$/, async (ctx) => {
    const [, marketId, side] = ctx.match;
    const { rows: [market] } = await db.query(`SELECT * FROM markets WHERE id = $1`, [marketId]);
    if (!market) return ctx.answerCbQuery("Market not found.", { show_alert: true });
    const emoji = side === "long" ? "📈" : "📉";
    await ctx.editMessageText(
      await marketCard(market) + `\n\n${emoji} *${side.toUpperCase()}* — How much?`,
      { parse_mode: "Markdown", ...liveMarketAmtKeyboard(marketId, side, ctx.from.id) },
    ).catch(() => {});
    await ctx.answerCbQuery();
  });

  // Queue-bet: amount selected → autosign a BatchBet into the queue.
  bot.action(/^marketqamt:(.+):(long|short):(\d+(?:\.\d+)?)$/, async (ctx) => {
    const [, marketId, side, amountStr] = ctx.match;
    const amount = parseFloat(amountStr);
    const emoji  = side === "long" ? "📈" : "📉";
    // Placement is DM-only — never autosign from a group callback (Codex P2).
    if (ctx.chat?.type !== "private") {
      return ctx.answerCbQuery("Open me in a private chat to bet.", { show_alert: true });
    }
    await ctx.answerCbQuery();

    const session = await getSession(ctx.from.id);
    if (!session) { await ctx.reply("🔗 Link your Telegram first. Use /start."); return; }

    const auto = await tryAutosignQueuedBet({
      userId:   session.userId,
      username: session.username,
      marketId,
      side:     side as "long" | "short",
      amount,
    });

    if (auto.ok) {
      const { rows: [m] } = await db.query(`SELECT symbol, ca, chain, timeframe FROM markets WHERE id = $1`, [marketId]);
      const queuedTicker = m ? (await resolveSafeDisplayTicker({ symbol: m.symbol, ca: m.ca ?? null, chain: m.chain })).displayTicker : "market";
      await ctx.editMessageText(
        `${emoji} *${side.toUpperCase()} $${amount}* on *${queuedTicker}*${m?.timeframe ? ` · ${m.timeframe}` : ""} — *Queued* ✅\n` +
        `⚙️ Executes in ~${auto.etaSeconds}s in the next batch.\n` +
        `🔗 [View market](${FRONTEND_URL}/market/${marketId})`,
        { parse_mode: "Markdown" },
      ).catch(() => {});
      return;
    }

    console.warn(`[bot] queue bet skip — userId=${session.userId} marketId=${marketId} skip=${auto.skip} detail="${auto.detail ?? ""}"`);
    const text =
      auto.skip === "market_unavailable"  ? `This market is no longer open for bets.` :
      auto.skip === "hard_cap"            ? `Trade exceeds maximum allowed.` :
      auto.skip === "no_balance"          ? `💸 Not enough USDC in your vault${auto.detail ? `: ${auto.detail}` : "."}` :
      auto.skip === "no_wallet"           ? `Wallet not set up yet — finish setup on fud.markets first.` :
      auto.skip === "no_consent" ||
      auto.skip === "consent_revoked" ||
      auto.skip === "no_privy_delegation" ? `Hey @${session.username}, enable Autosign in your fud.markets settings to trade from here.` :
      auto.skip === "feature_disabled"    ? `Autosign is temporarily paused for maintenance. Try again in a few minutes.` :
      `❌ Couldn't place the bet${auto.detail ? `: ${auto.detail}` : "."}`;
    await ctx.editMessageText(text, { parse_mode: "Markdown" }).catch(() => {});
  });

  // Queue-bet: back to side selection.
  bot.action(/^marketqback:(.+)$/, async (ctx) => {
    const [, marketId] = ctx.match;
    const { rows: [market] } = await db.query(`SELECT * FROM markets WHERE id = $1`, [marketId]);
    if (!market) return ctx.answerCbQuery("Market not found.", { show_alert: true });
    await ctx.editMessageText(await marketCard(market), { parse_mode: "Markdown", ...liveMarketSideKeyboard(marketId) }).catch(() => {});
    await ctx.answerCbQuery();
  });

  // /link <username> <password> — connect existing web account to this Telegram identity
  bot.command("link", async (ctx) => {
    ctx.deleteMessage().catch(() => {});
    const parts = ctx.message.text.trim().split(/\s+/);
    if (parts.length < 3) return ctx.reply("Usage: /link <username> <password>\nLinks your existing web account to this Telegram.");
    const [, username, password] = parts;

    let data: any;
    try {
      data = await apiFetch("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    } catch (e: any) {
      return ctx.reply(`❌ Login failed: ${e.message}`);
    }

    // Remove telegram_id from the auto-created account (if any), assign to web account
    await db.query(`UPDATE users SET telegram_id = NULL, telegram_username = NULL WHERE telegram_id = $1 AND id != $2`, [ctx.from.id, data.user.id]);
    await db.query(`UPDATE users SET telegram_id = $1, telegram_username = $2 WHERE id = $3`, [ctx.from.id, ctx.from.username ?? null, data.user.id]);
    sessions.set(ctx.from.id, { token: data.token, userId: data.user.id, username: data.user.username });

    await ctx.reply(
      `✅ Web account *${data.user.username}* linked to this Telegram\n\n` +
        `You can now discover tokens here and confirm trades on the web app.`,
      { parse_mode: "Markdown" }
    );
  });


  // /me
  bot.command("me", async (ctx) => {
    const session = await getSession(ctx.from.id);
    if (!session) {
      return ctx.reply("No account found. Use /start to register.");
    }
    const { rows: [user] } = await db.query(
      `SELECT username FROM users WHERE id = $1`, [session.userId]
    );
    if (!user) return ctx.reply("Account not found.");
    await ctx.reply(
      `👤 *${user.username}*\n\nCheck your balance and positions on FUD\\.markets`,
      {
        parse_mode: "MarkdownV2",
        ...Markup.inlineKeyboard([[
          Markup.button.url("🌐 Open FUD.markets", FRONTEND_URL),
        ]]),
      }
    );
  });

  // /settings — view or change bet presets
  // /x_reply <url> — manually queue a reply for a tweet that mentions didn't catch
  // (e.g. long-form posts where @FUDmarkets is outside the displayTextRange).
  // Admin-only.
  bot.command("x_reply", async (ctx) => {
    const adminIds = [process.env.ADMIN_TG_ID, process.env.ADMIN_TG_ID_2].filter(Boolean);
    if (!adminIds.includes(String(ctx.from.id))) {
      return ctx.reply("Only admins can use this command.");
    }
    const arg = ctx.message.text.trim().split(/\s+/).slice(1).join(" ").trim();
    if (!arg) return ctx.reply("Usage: /x_reply <tweet URL or ID>");
    await ctx.reply("⏳ Fetching tweet...");
    const result = await processMentionByUrl(arg);
    await ctx.reply(result.ok ? `✅ ${result.message}` : `❌ ${result.message}`);
  });

  // /x_test_reply <url|id> <text...>
  // Raw test of POST /2/tweets via OAuth1: replies to ANY tweet, even one that
  // never mentioned @FUDmarkets. Used to confirm whether self-serve API
  // actually enforces the "summons-only" reply restriction at runtime.
  // Bypasses Claude, approval queue, and mention filters. Admin-only.
  bot.command("x_test_reply", async (ctx) => {
    const adminIds = [process.env.ADMIN_TG_ID, process.env.ADMIN_TG_ID_2].filter(Boolean);
    if (!adminIds.includes(String(ctx.from.id))) {
      return ctx.reply("Only admins can use this command.");
    }
    const parts = ctx.message.text.trim().split(/\s+/).slice(1);
    if (parts.length < 2) {
      return ctx.reply("Usage: /x_test_reply <tweet URL or ID> <reply text>");
    }
    const urlOrId = parts[0];
    const text    = parts.slice(1).join(" ");
    const idMatch = urlOrId.match(/(\d{15,20})/);
    if (!idMatch) return ctx.reply("❌ Could not extract tweet ID from input.");
    const tweetId = idMatch[1];

    await ctx.reply(`⏳ POST /2/tweets\nreplyTo: ${tweetId}\ntext: "${text.slice(0, 200)}"`);
    try {
      const { status, data } = await postReply(text, tweetId);
      const newId = data?.data?.id ?? "?";
      const link  = newId !== "?" ? `https://x.com/FUDmarkets/status/${newId}` : "(no id returned)";
      const body  = JSON.stringify(data?.data ?? data).slice(0, 600);
      await ctx.reply(
        `✅ status=${status}\nnew tweet id: ${newId}\nlink: ${link}\n\nresponse.data:\n${body}`
      );
    } catch (e: any) {
      // Twitter API errors are JSON-encoded in e.message. Extract structured
      // fields only — don't echo the raw body, which can include developer
      // app metadata and stack frames.
      let msg = "API error";
      try {
        const errBody = JSON.parse(e?.message ?? "{}");
        const status  = errBody?.status  ?? "?";
        const title   = String(errBody?.title  ?? "Error").slice(0, 80);
        const detail  = String(errBody?.detail ?? "").slice(0, 200);
        msg = `${status} ${title}${detail ? `: ${detail}` : ""}`;
      } catch {
        msg = "Error (response not JSON)";
      }
      await ctx.reply(`❌ Error from POST /2/tweets:\n\n${msg}`);
    }
  });

  // /x_draft <url|id> [steering hint]
  // Fetches the target tweet (text + images), asks Claude (vision) to draft a
  // reply in "reply guy" voice, and queues it in the existing approval flow.
  // Approving with [Post] dispatches via the x-poster bypass, not OAuth1.
  bot.command("x_draft", async (ctx) => {
    const adminIds = [process.env.ADMIN_TG_ID, process.env.ADMIN_TG_ID_2].filter(Boolean);
    if (!adminIds.includes(String(ctx.from.id))) {
      return ctx.reply("Only admins can use this command.");
    }
    // Proactive replies disabled 2026-05-18 — bot only operates on mentions.
    // Re-enable by setting ENABLE_PROACTIVE_REPLIES=true if/when the flow is
    // revisited; the function code is kept dormant in x.ts for that purpose.
    if (process.env.ENABLE_PROACTIVE_REPLIES !== "true") {
      return ctx.reply("Proactive replies are disabled. The bot only responds to mentions now.");
    }
    const parts = ctx.message.text.trim().split(/\s+/).slice(1);
    if (parts.length < 1) {
      return ctx.reply("Usage: /x_draft <tweet URL or ID> [steering: bullish|bearish|meme|serio|duda|...]");
    }
    const urlOrId  = parts[0];
    const steering = parts.slice(1).join(" ").trim() || undefined;
    if (steering && steering.length > 60) {
      return ctx.reply("❌ steering hint too long (max 60 chars)");
    }

    await ctx.reply(`⏳ drafting${steering ? ` (steering: ${steering})` : ""}...`);
    const result = await draftProactiveReply(urlOrId, steering);
    await ctx.reply(result.ok ? `✅ ${result.message}` : `❌ ${result.message}`);
  });

  // /x_post_session <url|id> <text...>
  // Posts via the x-poster bypass service (Playwright UI automation).
  // Use for proactive replies that the official API would 403 on.
  // No secrets/URLs are echoed back to chat — only the safe error code.
  bot.command("x_post_session", async (ctx) => {
    const adminIds = [process.env.ADMIN_TG_ID, process.env.ADMIN_TG_ID_2].filter(Boolean);
    if (!adminIds.includes(String(ctx.from.id))) {
      return ctx.reply("Only admins can use this command.");
    }
    // Same kill-switch as /x_draft. x-poster session bypass was only ever
    // for proactive replies that the official API blocks; with proactive
    // off, this command has no remaining use case.
    if (process.env.ENABLE_PROACTIVE_REPLIES !== "true") {
      return ctx.reply("Proactive session posts are disabled. The bot only responds to mentions now.");
    }
    const parts = ctx.message.text.trim().split(/\s+/).slice(1);
    if (parts.length < 2) {
      return ctx.reply("Usage: /x_post_session <tweet URL or ID> <reply text>");
    }
    const urlOrId = parts[0];
    const text    = parts.slice(1).join(" ");
    const idMatch = urlOrId.match(/(\d{15,20})/);
    if (!idMatch) return ctx.reply("❌ Could not extract tweet ID from input.");
    const tweetId = idMatch[1];

    if (text.length > 280) {
      return ctx.reply(`❌ text too long (${text.length} chars, max 280)`);
    }

    await ctx.reply(`⏳ x-poster /reply (session bypass)\nreplyTo: ${tweetId}\ntext: "${text.slice(0, 200)}"`);
    const result = await postViaSession(text, tweetId, `tg:${ctx.from.id}:${tweetId}:${Date.now()}`);
    if (result.ok) {
      await ctx.reply(`✅ posted via session\nstatus=${result.status}`);
    } else {
      // result.error is a short code from x-poster (e.g. "session_expired",
      // "post_not_confirmed", "rate_limited"). Safe to echo.
      const safeError = (result.error ?? "unknown").slice(0, 200);
      await ctx.reply(`❌ x-poster failed\nstatus=${result.status}\nerror=${safeError}`);
    }
  });

  bot.command("settings", async (ctx) => {
    const parts = ctx.message.text.trim().split(/\s+/).slice(1);
    if (parts.length === 0) {
      const presets = getPresets(ctx.from.id);
      return ctx.reply(
        `⚙️ *Your bet presets:* $${presets.join(" · $")}\n\n` +
        `To change them: /settings 5 25 100 500`
      , { parse_mode: "Markdown" });
    }
    const nums = parts.map(Number).filter(n => !isNaN(n) && n > 0);
    if (nums.length !== 4) {
      return ctx.reply("You need exactly 4 amounts. E.g. /settings 5 25 100 500");
    }
    userPresets.set(ctx.from.id, nums);
    await ctx.reply(`✅ Presets updated: $${nums.join(" · $")}`);
  });

  // Catch all unhandled bot errors so they don't crash the process
  bot.catch((err: any) => {
    if (err?.response?.error_code === 400 && err?.response?.description?.includes("query is too old")) return;
    console.error("[bot:error]", err?.message ?? err);
  });

  // Register commands so they appear in the / menu
  bot.telegram.setMyCommands([
    { command: "start",    description: "Register or view your account" },
    { command: "search",   description: "Look up a token by CA: /search 0x… or base58" },
    { command: "markets",  description: "View currently open markets" },
    { command: "me",       description: "View your account" },
    { command: "settings", description: "View/change presets: /settings 5 25 100 500" },
    { command: "link",     description: "Link your web account: /link username password" },
    { command: "x_reply",         description: "[admin] Manually reply to a tweet: /x_reply <url>" },
    { command: "x_test_reply",    description: "[admin] Raw API reply test: /x_test_reply <url> <text>" },
    { command: "x_post_session",  description: "[admin] Post via session bypass: /x_post_session <url> <text>" },
    { command: "x_draft",         description: "[admin] AI-draft a reply (with vision): /x_draft <url> [tone]" },
  ]).catch((e) => console.error("[bot] setMyCommands error:", e.message));

  // Clear any webhook that might be blocking long-polling
  try {
    await bot.telegram.deleteWebhook({ drop_pending_updates: true });
  } catch (e) {
    console.warn("[bot] deleteWebhook failed (ignored):", e);
  }
  // ── X agent approval callbacks ──────────────────────────────────────────────
  bot.on("callback_query", async (ctx) => {
    const data = (ctx.callbackQuery as any).data as string | undefined;
    if (!data) return;

    // ── Post variant: xpost_{id}_{index} ──────────────────────────────────────
    const postMatch = data.match(/^xpost_(.+)_(\d+)$/);
    if (postMatch) {
      const [, callbackId, idxStr] = postMatch;
      const result = await handleXPost(callbackId, parseInt(idxStr));
      const label  = result === "posted" ? "✅ Posted!" : result === "expired" ? "⏱ Expired" : "⚠️ Error";
      await ctx.answerCbQuery(label).catch(() => {});
      return;
    }

    // ── Edit mode: xedit_{id} ──────────────────────────────────────────────
    if (data.startsWith("xedit_")) {
      const callbackId = data.slice("xedit_".length);
      const entry = getXPending(callbackId);
      if (!entry) { await ctx.answerCbQuery("⏱ Expired").catch(() => {}); return; }
      pendingXEdits.set(ctx.from!.id, { callbackId });
      await ctx.answerCbQuery("✏️ Send your reply").catch(() => {});
      const opts = entry.replies.map((r, i) => `[${i + 1}] ${r}`).join("\n\n");
      await ctx.reply(`✏️ *Edit reply for @${entry.xUsername}*\n\nCurrent options:\n${opts}\n\nSend your custom reply (max 270 chars):`, { parse_mode: "Markdown" });
      return;
    }

    // ── Confirm custom reply: xconfirm_{id} ───────────────────────────────
    if (data.startsWith("xconfirm_")) {
      const callbackId = data.slice("xconfirm_".length);
      const edit = [...pendingXEdits.entries()].find(([, v]) => v.callbackId === callbackId && v.customReply);
      if (!edit) { await ctx.answerCbQuery("⏱ Expired").catch(() => {}); return; }
      const [tgId, { customReply }] = edit;
      pendingXEdits.delete(tgId);
      const result = await handleXPostCustom(callbackId, customReply!);
      const label  = result === "posted" ? "✅ Posted!" : result === "expired" ? "⏱ Expired" : "⚠️ Error";
      await ctx.answerCbQuery(label).catch(() => {});
      return;
    }

    // ── Cancel edit: xcancel_{id} ──────────────────────────────────────────
    if (data.startsWith("xcancel_")) {
      const callbackId = data.slice("xcancel_".length);
      for (const [tgId, v] of pendingXEdits) {
        if (v.callbackId === callbackId) { pendingXEdits.delete(tgId); break; }
      }
      await ctx.answerCbQuery("Cancelled").catch(() => {});
      await ctx.reply("Edit cancelled.").catch(() => {});
      return;
    }

    // ── Reject: xreject_{id} ───────────────────────────────────────────────
    if (data.startsWith("xreject_")) {
      const callbackId = data.slice("xreject_".length);
      const result = await handleXReject(callbackId);
      const label  = result === "rejected" ? "❌ Rejected" : "⏱ Expired";
      await ctx.answerCbQuery(label).catch(() => {});
      return;
    }
  });

  bot.launch().catch((e: any) => console.error("[bot] launch error:", e?.message ?? e));
  console.log("🤖 Telegram bot started");

  process.once("SIGINT", () => bot.stop("SIGINT"));
  process.once("SIGTERM", () => bot.stop("SIGTERM"));
}
