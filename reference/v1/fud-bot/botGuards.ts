// Shared guards for the bot flows (Telegram + X).
//
// These bots create markets on behalf of users and hand off the bet to web.
// Before the handoff we need to ensure the user can actually complete the
// trade — otherwise we send them through a confirm/sign flow that's going
// to fail at the chain level and burn UX.

import { db } from "../db/client.js";
import { getUserBalance } from "../services/vaultService.js";
import { getUserBalanceV5 } from "../services/vaultV5Service.js";
import { getUserEmbeddedWallet, PrivyConfigError } from "../services/privyClient.js";
import { resolveSafeDisplayTicker } from "../services/tokenIdentity.js";

export type VaultBalanceResult =
  | { ok: true; vault: number; wallet: string }
  | { ok: false; reason: "no_wallet" | "rpc_error" };

/**
 * Vault balance pre-check. CRITICAL: uses ONLY vault balance, not wallet
 * USDC — placeBet pulls strictly from the vault, so adding wallet USDC
 * would produce false positives that fail at sign time.
 *
 * If users.wallet_address is null but the user has a privy_user_id, we
 * try a one-shot backfill: ask Privy for their embedded wallet and
 * persist it. This catches users whose web bootstrap finished before
 * Privy provisioned the wallet (race seen in production today — TG
 * bot showed "set up your wallet first" even after the user logged in
 * on web, because the link-wallet backfill only fires on /signBet).
 *
 * Returns:
 * - ok=true with vault amount and wallet address
 * - ok=false reason=no_wallet → user never went through web/Privy, no signer
 * - ok=false reason=rpc_error → transient; caller should soft-fail
 */
/** Resolve the user's signer wallet, backfilling from Privy on miss.
 *  Shared by the V4 and V5 balance checks. Returns null when the user
 *  never finished Privy wallet setup. */
async function resolveSignerWallet(userId: string): Promise<string | null> {
  const { rows: [u] } = await db.query(
    `SELECT wallet_address, privy_user_id FROM users WHERE id = $1`,
    [userId],
  );
  let wallet: string | null = u?.wallet_address ?? null;

  if (!wallet && u?.privy_user_id) {
    try {
      const embedded = await getUserEmbeddedWallet(u.privy_user_id);
      if (embedded?.address) {
        const addr = embedded.address.toLowerCase();
        const { rows: [taken] } = await db.query(
          `SELECT id FROM users WHERE wallet_address = $1 AND id != $2`, [addr, userId]
        );
        if (!taken) {
          await db.query(
            `UPDATE users SET wallet_address = $1, has_connected_wallet = true WHERE id = $2`,
            [addr, userId],
          );
          wallet = addr;
          console.log(`[bot-guards] backfilled wallet_address for user ${userId} from Privy`);
        }
      }
    } catch (e: any) {
      if (!(e instanceof PrivyConfigError)) {
        console.warn(`[bot-guards] Privy backfill failed for user ${userId}: ${e?.message ?? e}`);
      }
    }
  }
  return wallet;
}

export async function checkVaultBalance(userId: string): Promise<VaultBalanceResult> {
  const wallet = await resolveSignerWallet(userId);
  if (!wallet) return { ok: false, reason: "no_wallet" };
  try {
    const balanceStr = await getUserBalance(wallet as `0x${string}`);
    return { ok: true, vault: parseFloat(balanceStr), wallet };
  } catch {
    return { ok: false, reason: "rpc_error" };
  }
}

/** V5 vault balance pre-check — mirror of checkVaultBalance but reads the
 *  FUDVaultV5 contract (the rail bot markets now run on). getUserBalanceV5
 *  returns a bigint in 6-decimal USDC. 2026-05-25 bot→V5 migration. */
export async function checkVaultBalanceV5(userId: string): Promise<VaultBalanceResult> {
  const wallet = await resolveSignerWallet(userId);
  if (!wallet) return { ok: false, reason: "no_wallet" };
  try {
    const raw = await getUserBalanceV5(wallet as `0x${string}`);
    return { ok: true, vault: Number(raw) / 1e6, wallet };
  } catch {
    return { ok: false, reason: "rpc_error" };
  }
}

// DexScreener chainId slugs, keyed by our internal chain codes.
const DEX_CHAIN_MAP: Record<string, string> = {
  SOL: "solana", BASE: "base", ETH: "ethereum", BSC: "bsc", TRON: "tron",
  SUI: "sui", MONAD: "monad", POLYGON: "polygon", AVAX: "avalanche",
  PULSECHAIN: "pulsechain", TON: "ton", ABSTRACT: "abstract", HYPEREVM: "hyperevm", HOOD: "robinhood",
};

export interface TokenMeta {
  symbol: string;
  marketCap: number | null; // snapshot at open — drives draw/outlier thresholds at settlement
  // Display ticker for bot copy / public replies: the canonical ticker for a
  // real primary/alias (cbBTC→"BTC"), else the raw symbol. Impostors render
  // their raw ticker too — they are never canonical (no badge), and the flow
  // keys identity/price/settlement by CA, so a meme "SOL" can't be confused
  // with Solana. Prefer THIS over the raw `symbol` so aliases display canonically.
  safeDisplayTicker: string;
}

/**
 * Resolve a token's symbol + market cap from its contract address via
 * DexScreener. The V5 lazy open path needs a symbol (web resolves it
 * client-side; the bots resolve it here from the raw CA) AND the entry
 * market cap (web sends it from the client; the bot computes it here).
 *
 * Chain-aware + base/quote-oriented to MATCH the legacy /markets resolution
 * (markets.ts) — a TRON BTC CA must not resolve as a BASE market, and a
 * quote-side CA must not inherit the OTHER token's symbol/mcap. Codex
 * parity review 2026-05-25. Returns null when the CA has no priced pair on
 * the requested chain (→ silent skip / "token not found").
 */
export async function resolveTokenMetaFromCA(ca: string, chain: string): Promise<TokenMeta | null> {
  if (!ca) return null;
  // Strict supported-chain gate (Codex P1 2026-05-25): an LLM-emitted chain
  // label outside our map must NOT fall back to "any chain" — that let a
  // wrong-chain pair supply the symbol/mcap (and the bot would open a
  // wrong-chain market). Unknown chain → refuse to resolve.
  const chainId = DEX_CHAIN_MAP[chain?.toUpperCase()] ?? null;
  if (!chainId) return null;
  try {
    const url = `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(ca)}`;
    // 5s timeout — a hung DexScreener socket would otherwise pin the bot
    // handler (Node fetch waits indefinitely). code-reviewer HIGH 2026-05-25.
    const res = await fetch(url, {
      headers: { "User-Agent": "FUDMarkets/1.0" },
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) return null;
    const data = await res.json() as any;
    const pairs = (data.pairs ?? []).filter((p: any) => p.priceUsd && parseFloat(p.priceUsd) > 0);
    if (!pairs.length) return null;
    // Only pairs on the requested chain (strict — no any-chain fallback).
    const onChain = pairs.filter((p: any) => p.chainId === chainId);
    if (!onChain.length) return null;
    // Prefer the pool where our CA is the BASE side — symbol + mcap are only
    // reliable from the base token. Fall back to highest-liquidity otherwise.
    const caL = ca.toLowerCase();
    const oriented: { p: any; base: boolean }[] = onChain
      .map((p: any) => ({ p, base: p.baseToken?.address?.toLowerCase() === caL }))
      .sort((a: { p: any }, b: { p: any }) => (b.p.liquidity?.usd ?? 0) - (a.p.liquidity?.usd ?? 0));
    const chosen = oriented.find((x) => x.base) ?? oriented[0];
    const symbol = (chosen.base ? chosen.p.baseToken?.symbol : chosen.p.quoteToken?.symbol) ?? chosen.p.baseToken?.symbol;
    if (!symbol) return null;
    // mcap only trustworthy from the base side (DexScreener reports it for
    // baseToken only); null for quote-side pools.
    const rawMcap = chosen.base ? (chosen.p.marketCap ?? chosen.p.fdv ?? null) : null;
    const marketCap = typeof rawMcap === "number" && rawMcap > 0 ? rawMcap : null;
    const symU = String(symbol).toUpperCase();
    const ident = await resolveSafeDisplayTicker({ symbol: symU, ca, chain });
    return { symbol: symU, marketCap, safeDisplayTicker: ident.displayTicker };
  } catch {
    return null;
  }
}

/** Banned-token guard — parity with the legacy POST /markets check.
 *  Refuse to open markets on CAs an admin has flagged. */
export async function isTokenBanned(ca: string, chain: string): Promise<boolean> {
  if (!ca) return false;
  const { rows: [banned] } = await db.query(
    `SELECT 1 FROM banned_tokens WHERE LOWER(ca) = LOWER($1) AND UPPER(chain) = UPPER($2) LIMIT 1`,
    [ca, chain],
  );
  return !!banned;
}

/**
 * Rate limit per-user for market creation via bots. In-memory bucket.
 * Cap: 1 market per 30s, max 20/day. Reset daily at process start.
 *
 * Why in-memory: bot runs in single Node process. Restart resets counters,
 * which is acceptable for pre-launch. If we move bots to a separate worker
 * later, swap for Redis or DB-backed buckets.
 */
const lastMarketByUser  = new Map<string, number>();
const dailyCountByUser  = new Map<string, { count: number; resetAt: number }>();
const COOLDOWN_MS       = 30_000;
const DAILY_CAP         = 20;
const DAY_MS            = 24 * 60 * 60 * 1000;

export type RateLimitResult =
  | { ok: true }
  | { ok: false; reason: "cooldown"; retryInSec: number }
  | { ok: false; reason: "daily_cap" };

export function checkMarketCreationRateLimit(userId: string): RateLimitResult {
  const now = Date.now();
  const last = lastMarketByUser.get(userId) ?? 0;
  const sinceLast = now - last;
  if (sinceLast < COOLDOWN_MS) {
    return { ok: false, reason: "cooldown", retryInSec: Math.ceil((COOLDOWN_MS - sinceLast) / 1000) };
  }
  const daily = dailyCountByUser.get(userId);
  if (daily && now < daily.resetAt) {
    if (daily.count >= DAILY_CAP) return { ok: false, reason: "daily_cap" };
  }
  return { ok: true };
}

export function recordMarketCreation(userId: string): void {
  const now = Date.now();
  lastMarketByUser.set(userId, now);
  const daily = dailyCountByUser.get(userId);
  if (!daily || now >= daily.resetAt) {
    dailyCountByUser.set(userId, { count: 1, resetAt: now + DAY_MS });
  } else {
    daily.count += 1;
  }
}
