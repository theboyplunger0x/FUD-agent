// Bot autosign — orchestrator.
//
// Glues together:
//   - bot_autosign_consents (delegation record, two-state: active/revoked)
//   - vault balance pre-check (existing botGuards.checkVaultBalance)
//   - Privy server-side EIP-712 signing (privyClient.signBetTypedData)
//   - executeSignedBet (shared atomic core)
//
// One entry point: tryAutosignBet(). Returns:
//   - { ok: true, position, onchainTx } — bet placed, autosign was used
//   - { ok: false, reason } — fall through to web handoff (reason explains why)
//
// Design (2026-05-12, Marcos): NO user-configurable caps. NO expiration.
// Vault balance is the natural ceiling. AUTOSIGN_ENABLED is our kill
// switch. A single hardcoded HARD_CAP_PER_TRADE guards against LLM
// hallucination in the X bot's tweet parser (e.g. "$9999999 short" →
// rejected). User doesn't see this; it's defensive programming.

import { db } from "../db/client.js";
import { recoverTypedDataAddress } from "viem";
import { checkVaultBalance, checkVaultBalanceV5 } from "../fud-bot/botGuards.js";
import { getUserDelegatedWallet, signBetTypedData, signLazyBetTypedData, signBatchBetTypedData, PrivyConfigError, PrivyRpcError } from "./privyClient.js";
import { getUserNonce, VAULT_CONFIG } from "./vaultService.js";
import { buildLazyBetTypedDataDomain, LAZY_BET_TYPES, BATCH_BET_TYPES } from "./vaultV5Service.js";
import { executeSignedBet } from "./betService.js";
import { prepareLazyOpenTerms, openLazyMarket, takeLazyMarket, prepareQueuedBet, queueBet, peekNextLazyNonce, SIGNATURE_TTL_SECONDS, LazyOpenError } from "./lazyMarketService.js";
import { getFlags } from "../lib/featureFlags.js";
import type { Timeframe } from "../lib/market.js";

export const AUTOSIGN_ENABLED = process.env.AUTOSIGN_ENABLED === "1";

/** Ops kill switches mirror the web V5 routes: maintenance_mode and
 *  betting_enabled must pause the bot too (it bypasses the HTTP routes that
 *  enforce them). Returns a feature_disabled skip when trading is paused, or
 *  null when clear. Codex P2 2026-05-25. */
function tradingPausedSkip(): { ok: false; skip: AutosignSkipReason; detail: string } | null {
  const flags = getFlags();
  if (flags.maintenance_mode) return { ok: false, skip: "feature_disabled", detail: "maintenance" };
  if (!flags.betting_enabled) return { ok: false, skip: "feature_disabled", detail: "betting_disabled" };
  return null;
}

// Anti-LLM-hallucination ceiling. Not exposed as user-configurable.
// Bump if real demand shows up; lower if abuse surfaces.
const HARD_CAP_PER_TRADE = 5_000;

export type AutosignSkipReason =
  | "feature_disabled"
  | "no_consent"
  | "consent_revoked"
  | "hard_cap"
  | "no_balance"
  | "no_wallet"
  | "vault_rpc_error"        // transient — vault read failed, retry later
  | "no_privy_delegation"
  | "privy_unavailable"
  | "recover_mismatch"
  | "bet_rejected";          // executeSignedBet returned !ok

export type AutosignAttemptInput = {
  userId:    string;
  username?: string;
  marketId:  string;
  onchainMarketId: number;
  side:      "long" | "short";
  amount:    number;
  message?:  string | null;
};

export type AutosignAttemptResult =
  | { ok: true; position: Record<string, unknown>; onchainTx: string | null }
  | {
      ok: false;
      skip: AutosignSkipReason;
      detail?: string;
      // When true, the rejection is platform-wide (cap exceeded,
      // market expired, etc.) and going to the web fallback link
      // will also fail. Bots should communicate the rejection
      // directly instead of sending the user to a doomed handoff.
      // Codex 2026-05-12.
      terminal?: boolean;
    };

type ConsentRow = {
  user_id:         string;
  privy_user_id:   string;
  wallet_address:  string;
  privy_wallet_id: string | null;
  revoked_at:      Date | null;
};

async function getActiveConsent(userId: string): Promise<ConsentRow | null> {
  const { rows: [row] } = await db.query(
    `SELECT user_id, privy_user_id, wallet_address, privy_wallet_id, revoked_at
       FROM bot_autosign_consents
      WHERE user_id = $1 AND revoked_at IS NULL`,
    [userId],
  );
  return row ?? null;
}

/** Cheap precheck for bots: does this user have an active Autosign consent right now?
 *  Used to short-circuit the create_market → autosign flow before we waste
 *  a chain tx creating a market for a user we can't autosign for.
 *
 *  Returns a tagged result so callers can distinguish between user-level
 *  problems (`no_consent` — never enabled, or no Privy delegation bound)
 *  and operator-level problems (`feature_disabled` — kill switch off, the
 *  user IS set up but the service is paused). Codex Pass 9 P2: collapsing
 *  both into a single boolean told a fully-onboarded user to "go enable
 *  Autosign" during an operator pause. */
export type AutosignGateResult =
  | { ok: true }
  | { ok: false; reason: "feature_disabled" | "no_consent" };

export async function checkAutosignGate(userId: string): Promise<AutosignGateResult> {
  if (!AUTOSIGN_ENABLED) return { ok: false, reason: "feature_disabled" };
  const row = await getActiveConsent(userId);
  if (!row) return { ok: false, reason: "no_consent" };
  if (!row.privy_wallet_id) return { ok: false, reason: "no_consent" };
  return { ok: true };
}

/** Backwards-compatible boolean wrapper. New callers should use
 *  `checkAutosignGate` so they can branch on the reason and surface a
 *  service-paused message vs a setup-needed message. */
export async function hasActiveAutosignConsent(userId: string): Promise<boolean> {
  return (await checkAutosignGate(userId)).ok;
}

/**
 * Best-effort autosign. Caller (TG/X bot) should fall through to the
 * web deep-link handoff on any { ok: false }.
 *
 * Critical guarantees:
 *  1. Hard cap against LLM hallucination ($5000 hardcoded ceiling).
 *  2. Vault balance checked before any signing (no wasted Privy RPC).
 *  3. ecrecover validates Privy's signature matches the consented wallet
 *     before submitting on-chain — defense in depth.
 *  4. Postgres advisory lock per-user wraps the nonce → sign → submit
 *     window so concurrent Telegram + X tweets don't race on nonce.
 */
export async function tryAutosignBet(input: AutosignAttemptInput): Promise<AutosignAttemptResult> {
  if (!AUTOSIGN_ENABLED) return { ok: false, skip: "feature_disabled" };

  const consent = await getActiveConsent(input.userId);
  if (!consent) return { ok: false, skip: "no_consent" };

  // Hard cap — defensive against LLM hallucination, not user-visible.
  // Terminal: even on web the bet would hit MAX_SINGLE_BET (which is
  // tighter than this), so a fallback link is dead-end UX.
  if (input.amount > HARD_CAP_PER_TRADE) {
    return { ok: false, skip: "hard_cap", detail: `>${HARD_CAP_PER_TRADE}`, terminal: true };
  }

  // Vault balance pre-check — reuse the shared helper. Distinguish
  // between `no_wallet` (terminal — user never finished Privy setup,
  // sending them anywhere won't help) and `rpc_error` (transient —
  // the vault read failed, a retry will likely succeed). Codex Pass 9
  // P1: collapsing both into a terminal "no wallet" skip teaches the
  // user that their setup is broken when really the infra blipped.
  const balance = await checkVaultBalance(input.userId);
  if (!balance.ok) {
    if (balance.reason === "rpc_error") {
      return { ok: false, skip: "vault_rpc_error", detail: balance.reason };
    }
    return { ok: false, skip: "no_wallet", detail: balance.reason, terminal: true };
  }
  if (balance.vault < input.amount) {
    // Insufficient balance = bet would fail on web too. Terminal.
    return { ok: false, skip: "no_balance", detail: `need ${input.amount} have ${balance.vault}`, terminal: true };
  }

  // Consent wallet must match the actual vault wallet — paranoia
  // against stale consent rows after a wallet rebind.
  if (balance.wallet.toLowerCase() !== consent.wallet_address.toLowerCase()) {
    return { ok: false, skip: "no_wallet", detail: "consent wallet mismatch", terminal: true };
  }

  if (!consent.privy_wallet_id) {
    // Web sign still works without Privy delegation — not terminal.
    return { ok: false, skip: "no_privy_delegation", detail: "no wallet_id stored" };
  }

  // Postgres advisory lock per-user: protects the nonce → sign →
  // submit window from concurrent autosign attempts (e.g. same user
  // tweets the same intent on both TG and X). Lock key = hash of userId.
  const lockKey = hashUserIdToBigInt(input.userId);
  const client  = await db.connect();
  let lockHeld = false;
  try {
    await client.query("SELECT pg_advisory_lock($1)", [lockKey]);
    lockHeld = true;

    // Retry loop for non-terminal failures. Most "didn't land" cases
    // are transient: stale RPC simulate, nonce race, Privy 5xx blip.
    // Retrying with fresh nonce + fresh deadline resolves ~90% before
    // the bot ever has to tweet "place from web". Marcos 2026-05-18.
    //
    // Terminal failures (hard_cap, no_wallet, no_balance, recover_mismatch,
    // bet_rejected with terminal=true) short-circuit immediately — no
    // point retrying something the user has to fix.
    const MAX_BET_ATTEMPTS = 3;
    const BACKOFF_MS       = [0, 2_500, 5_000]; // 0s, 2.5s, 5s

    let lastResult: AutosignAttemptResult = { ok: false, skip: "bet_rejected", detail: "no attempt run" };
    for (let attempt = 0; attempt < MAX_BET_ATTEMPTS; attempt++) {
      if (BACKOFF_MS[attempt] > 0) {
        await new Promise(r => setTimeout(r, BACKOFF_MS[attempt]));
      }

      let nonce: bigint;
      try {
        nonce = await getUserNonce(consent.wallet_address as `0x${string}`);
      } catch (e: any) {
        console.error(`[autosign] attempt ${attempt + 1}/${MAX_BET_ATTEMPTS} getUserNonce failed: ${e.message}`);
        lastResult = { ok: false, skip: "privy_unavailable", detail: "nonce fetch" };
        continue;
      }
      const deadline  = BigInt(Math.floor(Date.now() / 1000) + 300);
      const amountRaw = BigInt(Math.round(input.amount * 1_000_000));
      const sideEnum  = input.side === "long" ? 0 : 1;

      const domain = {
        name:              VAULT_CONFIG.name,
        version:           VAULT_CONFIG.version,
        chainId:           VAULT_CONFIG.chainId,
        verifyingContract: VAULT_CONFIG.address as `0x${string}`,
      };
      const message = {
        marketId: input.onchainMarketId.toString(),
        user:     consent.wallet_address as `0x${string}`,
        side:     sideEnum,
        amount:   amountRaw.toString(),
        nonce:    nonce.toString(),
        deadline: deadline.toString(),
      };

      let signature: `0x${string}`;
      try {
        signature = await signBetTypedData({
          walletId: consent.privy_wallet_id,
          domain,
          message,
        });
      } catch (e: any) {
        if (e instanceof PrivyConfigError) {
          console.error("[autosign] Privy not configured:", e.message);
          // Terminal — no point retrying when env is missing.
          return { ok: false, skip: "feature_disabled", detail: "no PRIVY_APP_SECRET" };
        }
        if (e instanceof PrivyRpcError) {
          console.error(`[autosign] attempt ${attempt + 1} Privy RPC ${e.status}:`, e.body);
          lastResult = { ok: false, skip: "privy_unavailable", detail: `${e.status}` };
          continue;
        }
        console.error(`[autosign] attempt ${attempt + 1} Privy unexpected:`, e);
        lastResult = { ok: false, skip: "privy_unavailable", detail: "unknown" };
        continue;
      }

      // ecrecover defense-in-depth.
      const recovered = await recoverTypedDataAddress({
        domain,
        types: {
          Bet: [
            { name: "marketId", type: "uint256" },
            { name: "user",     type: "address" },
            { name: "side",     type: "uint8"   },
            { name: "amount",   type: "uint256" },
            { name: "nonce",    type: "uint256" },
            { name: "deadline", type: "uint256" },
          ],
        },
        primaryType: "Bet",
        message: {
          marketId: BigInt(message.marketId),
          user:     message.user,
          side:     message.side,
          amount:   BigInt(message.amount),
          nonce:    BigInt(message.nonce),
          deadline: BigInt(message.deadline),
        },
        signature,
      });
      if (recovered.toLowerCase() !== consent.wallet_address.toLowerCase()) {
        console.error("[autosign] SECURITY: recover mismatch", { recovered, expected: consent.wallet_address });
        // Terminal: signature doesn't match wallet, retry won't help.
        return { ok: false, skip: "recover_mismatch", detail: recovered };
      }

      const result = await executeSignedBet({
        userId:         input.userId,
        username:       input.username,
        marketId:       input.marketId,
        side:           input.side,
        amount:         input.amount,
        message:        input.message,
        signature,
        walletAddress:  consent.wallet_address as `0x${string}`,
        signedNonce:    nonce.toString(),
        signedDeadline: deadline.toString(),
      });

      if (result.ok) {
        if (attempt > 0) {
          console.log(`[autosign] succeeded on attempt ${attempt + 1}/${MAX_BET_ATTEMPTS} after transient failure`);
        }
        return { ok: true, position: result.position, onchainTx: result.onchainTx };
      }

      console.warn(`[autosign] attempt ${attempt + 1}/${MAX_BET_ATTEMPTS} bet_rejected userId=${input.userId} terminal=${result.terminal ?? false} detail="${result.error}"`);
      lastResult = {
        ok: false,
        skip: "bet_rejected",
        detail: result.error,
        terminal: result.terminal,
      };
      // Terminal rejection — short-circuit out of retry loop.
      if (result.terminal) break;
    }
    return lastResult;
  } finally {
    if (lockHeld) {
      try { await client.query("SELECT pg_advisory_unlock($1)", [lockKey]); } catch {}
    }
    client.release();
  }
}

function hashUserIdToBigInt(userId: string): string {
  let h = 5381n;
  for (let i = 0; i < userId.length; i++) {
    h = ((h << 5n) + h + BigInt(userId.charCodeAt(i))) & 0x7fffffffffffffffn;
  }
  return h.toString();
}

// ─── V5 lazy autosign (bot market open) ─────────────────────────────────────
//
// The V5 equivalent of tryAutosignBet. Where the V4 path eagerly created a
// market + signed a placeBet, V5 is lazy: the opener signs a LazyBet intent
// that we store as a 'pending' market + earmark. The matcher later finds a
// taker and submits createAndPlaceBet on-chain. So this function NEVER touches
// the chain itself — it signs the intent via Privy and persists it through the
// same shared core (lazyMarketService.openLazyMarket) the web route uses.
// 2026-05-25 bot→V5 migration (Codex-reviewed plan).

export type AutosignLazyInput = {
  userId:   string;
  username?: string;
  symbol:   string;
  chain:    string;
  ca:       string | null;
  timeframe: Timeframe;
  side:     "long" | "short";
  amount:   number;
  tagline?: string | null;
  // Snapshot market cap at open — drives draw/outlier thresholds at
  // settlement (web sends it from the client; bots resolve it from the CA).
  // For whitelisted canonical majors the caller may leave this null — we
  // force the big-cap sentinel below, mirroring the legacy /markets path.
  entryMarketCap?: number | null;
};

export type AutosignLazyResult =
  | { ok: true; pendingMarketId: string; entryPrice: number; symbol: string }
  | { ok: false; skip: AutosignSkipReason; detail?: string; terminal?: boolean };

export async function tryAutosignLazyMarket(input: AutosignLazyInput): Promise<AutosignLazyResult> {
  if (!AUTOSIGN_ENABLED) return { ok: false, skip: "feature_disabled" };
  const paused = tradingPausedSkip();
  if (paused) return paused;

  const consent = await getActiveConsent(input.userId);
  if (!consent) return { ok: false, skip: "no_consent" };

  if (input.amount > HARD_CAP_PER_TRADE) {
    return { ok: false, skip: "hard_cap", detail: `>${HARD_CAP_PER_TRADE}`, terminal: true };
  }

  // V5 vault balance pre-check (the rail bot markets now run on). Distinguish
  // transient rpc_error (retryable) from terminal no_wallet / no_balance.
  const balance = await checkVaultBalanceV5(input.userId);
  if (!balance.ok) {
    if (balance.reason === "rpc_error") return { ok: false, skip: "vault_rpc_error", detail: balance.reason };
    return { ok: false, skip: "no_wallet", detail: balance.reason, terminal: true };
  }
  if (balance.vault < input.amount) {
    return { ok: false, skip: "no_balance", detail: `need ${input.amount} have ${balance.vault}`, terminal: true };
  }
  if (balance.wallet.toLowerCase() !== consent.wallet_address.toLowerCase()) {
    return { ok: false, skip: "no_wallet", detail: "consent wallet mismatch", terminal: true };
  }
  if (!consent.privy_wallet_id) {
    return { ok: false, skip: "no_privy_delegation", detail: "no wallet_id stored" };
  }

  // Per-user advisory lock: serialize the peek→sign→CAS window so concurrent
  // X + Telegram opens for the same user don't race on the lazyNonce.
  const lockKey  = hashUserIdToBigInt(input.userId);
  const client   = await db.connect();
  let lockHeld   = false;
  try {
    await client.query("SELECT pg_advisory_lock($1)", [lockKey]);
    lockHeld = true;

    const MAX_ATTEMPTS = 3;
    const BACKOFF_MS    = [0, 2_500, 5_000];
    let lastResult: AutosignLazyResult = { ok: false, skip: "bet_rejected", detail: "no attempt run" };

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      if (BACKOFF_MS[attempt] > 0) await new Promise((r) => setTimeout(r, BACKOFF_MS[attempt]));

      // Fresh terms each attempt — a nonce conflict re-peeks the next value.
      let terms;
      try {
        terms = await prepareLazyOpenTerms({
          userId: input.userId, symbol: input.symbol, chain: input.chain,
          ca: input.ca, timeframe: input.timeframe,
        });
      } catch (e: any) {
        // Price fetch failed (502) — transient, retry.
        lastResult = { ok: false, skip: "bet_rejected", detail: e instanceof LazyOpenError ? e.message : String(e?.message ?? e) };
        continue;
      }

      const sideEnum  = input.side === "long" ? 0 : 1;
      const amountRaw = BigInt(Math.round(input.amount * 1e6)).toString();
      const domain    = buildLazyBetTypedDataDomain();
      const message   = {
        user:       consent.wallet_address as `0x${string}`,
        side:       sideEnum,
        amount:     amountRaw,
        closesAt:   String(terms.closesAtUnix),
        entryPrice: terms.entryPriceScaled,
        lazyNonce:  terms.lazyNonce,
        deadline:   String(terms.deadline),
      };

      let signature: `0x${string}`;
      try {
        signature = await signLazyBetTypedData({ walletId: consent.privy_wallet_id, domain, message });
      } catch (e: any) {
        if (e instanceof PrivyConfigError) {
          return { ok: false, skip: "feature_disabled", detail: "no PRIVY_APP_SECRET" };
        }
        if (e instanceof PrivyRpcError) {
          console.error(`[autosign-lazy] attempt ${attempt + 1} Privy RPC ${e.status}:`, e.body);
          lastResult = { ok: false, skip: "privy_unavailable", detail: `${e.status}` };
          continue;
        }
        console.error(`[autosign-lazy] attempt ${attempt + 1} Privy unexpected:`, e);
        lastResult = { ok: false, skip: "privy_unavailable", detail: "unknown" };
        continue;
      }

      // ecrecover defense-in-depth — signature must match the consented wallet.
      const recovered = await recoverTypedDataAddress({
        domain,
        types: LAZY_BET_TYPES,
        primaryType: "LazyBet",
        message: {
          user:       message.user,
          side:       sideEnum,
          amount:     BigInt(message.amount),
          closesAt:   BigInt(message.closesAt),
          entryPrice: BigInt(message.entryPrice),
          lazyNonce:  BigInt(message.lazyNonce),
          deadline:   BigInt(message.deadline),
        },
        signature,
      });
      if (recovered.toLowerCase() !== consent.wallet_address.toLowerCase()) {
        console.error("[autosign-lazy] SECURITY: recover mismatch", { recovered, expected: consent.wallet_address });
        return { ok: false, skip: "recover_mismatch", detail: recovered };
      }

      // Whitelisted canonical majors (Pyth/CB-backed) → force big-cap draw
      // thresholds via the MAX_SAFE_INTEGER sentinel, exactly as legacy
      // /markets did. Otherwise use the caller-supplied DexScreener mcap.
      const entryMarketCap = terms.canonical ? Number.MAX_SAFE_INTEGER : (input.entryMarketCap ?? null);

      // Persist via the shared core. The stored row carries the EXACT signed
      // terms so the matcher can reconstruct + submit the LazyBet on-chain.
      try {
        const result = await openLazyMarket({
          userId:        input.userId,
          walletAddress: consent.wallet_address,
          symbol:        input.symbol,
          chain:         input.chain,
          ca:            input.ca,
          timeframe:     input.timeframe,
          side:          input.side,
          amountStr:     String(input.amount),
          signature,
          lazyNonce:     terms.lazyNonce,
          deadline:      terms.deadline,
          closesAt:      terms.closesAtUnix,
          entryPrice:    terms.entryPrice,
          entryMarketCap,
          tagline:       input.tagline ?? null,
        });
        if (attempt > 0) {
          console.log(`[autosign-lazy] succeeded on attempt ${attempt + 1}/${MAX_ATTEMPTS} after transient failure`);
        }
        return { ok: true, pendingMarketId: result.pendingMarketId, entryPrice: terms.entryPrice, symbol: input.symbol };
      } catch (e: any) {
        if (e instanceof LazyOpenError) {
          // Nonce conflict — another action ate the nonce. Re-prepare + retry.
          if (e.code === "nonce_conflict") {
            lastResult = { ok: false, skip: "bet_rejected", detail: e.message };
            continue;
          }
          // Everything else here is a deterministic rejection a retry won't fix.
          const skip: AutosignSkipReason = e.code === "insufficient" ? "no_balance" : "bet_rejected";
          lastResult = { ok: false, skip, detail: e.message, terminal: true };
          break;
        }
        console.error(`[autosign-lazy] attempt ${attempt + 1} openLazyMarket unexpected:`, e);
        lastResult = { ok: false, skip: "bet_rejected", detail: e?.message ?? "unknown" };
        continue;
      }
    }
    return lastResult;
  } finally {
    if (lockHeld) {
      try { await client.query("SELECT pg_advisory_unlock($1)", [lockKey]); } catch {}
    }
    client.release();
  }
}

// ─── V5 lazy autosign (bot TAKE the other side) ─────────────────────────────
//
// Bot equivalent of POST /markets/lazy/:id/take. The taker signs a LazyBet
// for the OPPOSITE side of a pending market, using the OPENER's closesAt +
// entryPrice (same market) but the taker's own side/amount/nonce/deadline.
// Persists via the shared takeLazyMarket() core; the matcher then pairs them
// on-chain. 2026-05-25 — the TG "take the other side" button.

export type AutosignLazyTakeInput = {
  userId:    string;
  username?: string;
  pendingId: string;
  // Taker stake. Defaults to the opener's amount (symmetric "take the other
  // side" button). Asymmetric is allowed by the contract (multiplier mechanic).
  amount?:   number;
};

export type AutosignLazyTakeResult =
  | { ok: true; pendingMarketId: string; symbol: string; ca: string | null; chain: string; takerSide: "long" | "short"; amount: number }
  | { ok: false; skip: AutosignSkipReason | "take_unavailable"; detail?: string; terminal?: boolean };

export async function tryAutosignLazyTake(input: AutosignLazyTakeInput): Promise<AutosignLazyTakeResult> {
  if (!AUTOSIGN_ENABLED) return { ok: false, skip: "feature_disabled" };
  const paused = tradingPausedSkip();
  if (paused) return paused;

  const consent = await getActiveConsent(input.userId);
  if (!consent) return { ok: false, skip: "no_consent" };
  if (!consent.privy_wallet_id) return { ok: false, skip: "no_privy_delegation", detail: "no wallet_id stored" };

  // Fetch the pending market terms the taker must sign against.
  const { rows: [pending] } = await db.query<{
    id: string; opener_user_id: string; side: "long" | "short"; amount: string;
    entry_price: string; closes_at: Date; expires_at: Date; status: string;
    symbol: string; ca: string | null; chain: string;
  }>(
    `SELECT id, opener_user_id, side, amount, entry_price, closes_at, expires_at, status, symbol, ca, chain
       FROM pending_markets WHERE id = $1`,
    [input.pendingId],
  );
  if (!pending) return { ok: false, skip: "take_unavailable", detail: "not_found", terminal: true };
  if (pending.status !== "pending") return { ok: false, skip: "take_unavailable", detail: pending.status, terminal: true };
  if (new Date(pending.expires_at) <= new Date() || new Date(pending.closes_at) <= new Date()) {
    return { ok: false, skip: "take_unavailable", detail: "expired", terminal: true };
  }
  if (pending.opener_user_id === input.userId) {
    return { ok: false, skip: "take_unavailable", detail: "own_market", terminal: true };
  }

  const takerSide: "long" | "short" = pending.side === "long" ? "short" : "long";
  // Keep the amount as a string end-to-end. pending.amount is a PG NUMERIC
  // (driver returns a string like "25.000000"); routing it through Number→String
  // risks scientific notation that fails the service regex. code-reviewer MEDIUM.
  const takerAmountStr = input.amount != null ? String(input.amount) : String(pending.amount);
  const takerAmount = Number(takerAmountStr);
  if (!(takerAmount > 0)) return { ok: false, skip: "take_unavailable", detail: "bad_amount", terminal: true };
  if (takerAmount > HARD_CAP_PER_TRADE) {
    return { ok: false, skip: "hard_cap", detail: `>${HARD_CAP_PER_TRADE}`, terminal: true };
  }

  // V5 balance pre-check.
  const balance = await checkVaultBalanceV5(input.userId);
  if (!balance.ok) {
    if (balance.reason === "rpc_error") return { ok: false, skip: "vault_rpc_error", detail: balance.reason };
    return { ok: false, skip: "no_wallet", detail: balance.reason, terminal: true };
  }
  if (balance.vault < takerAmount) {
    return { ok: false, skip: "no_balance", detail: `need ${takerAmount} have ${balance.vault}`, terminal: true };
  }
  if (balance.wallet.toLowerCase() !== consent.wallet_address.toLowerCase()) {
    return { ok: false, skip: "no_wallet", detail: "consent wallet mismatch", terminal: true };
  }

  // The taker signs the OPENER's closesAt + entryPrice (same market) so the
  // two LazyBets agree on the terms createAndPlaceBet will use.
  const closesAtUnix = Math.floor(new Date(pending.closes_at).getTime() / 1000);
  const entryPriceScaled = Math.round(parseFloat(pending.entry_price) * 1e8).toString();
  const sideEnum  = takerSide === "long" ? 0 : 1;
  const amountRaw = BigInt(Math.round(takerAmount * 1e6)).toString();
  const domain    = buildLazyBetTypedDataDomain();

  // Lock scopes to THIS TAKER's userId — prevents same-user double-sign across
  // concurrent TG/X attempts. Cross-user races (two different takers on the
  // same pending) are serialized by the FOR UPDATE inside takeLazyMarket, not
  // here. code-reviewer HIGH 2026-05-25.
  const lockKey  = hashUserIdToBigInt(input.userId);
  const client   = await db.connect();
  let lockHeld   = false;
  try {
    await client.query("SELECT pg_advisory_lock($1)", [lockKey]);
    lockHeld = true;

    const MAX_ATTEMPTS = 3;
    const BACKOFF_MS    = [0, 2_500, 5_000];
    let lastResult: AutosignLazyTakeResult = { ok: false, skip: "bet_rejected", detail: "no attempt run" };

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      if (BACKOFF_MS[attempt] > 0) await new Promise((r) => setTimeout(r, BACKOFF_MS[attempt]));

      const lazyNonce = (await peekNextLazyNonce(input.userId)).toString();
      const deadline  = Math.floor(Date.now() / 1000) + SIGNATURE_TTL_SECONDS;
      const message = {
        user:       consent.wallet_address as `0x${string}`,
        side:       sideEnum,
        amount:     amountRaw,
        closesAt:   String(closesAtUnix),
        entryPrice: entryPriceScaled,
        lazyNonce,
        deadline:   String(deadline),
      };

      let signature: `0x${string}`;
      try {
        signature = await signLazyBetTypedData({ walletId: consent.privy_wallet_id, domain, message });
      } catch (e: any) {
        if (e instanceof PrivyConfigError) return { ok: false, skip: "feature_disabled", detail: "no PRIVY_APP_SECRET" };
        if (e instanceof PrivyRpcError) {
          console.error(`[autosign-take] attempt ${attempt + 1} Privy RPC ${e.status}:`, e.body);
          lastResult = { ok: false, skip: "privy_unavailable", detail: `${e.status}` };
          continue;
        }
        console.error(`[autosign-take] attempt ${attempt + 1} Privy unexpected:`, e);
        lastResult = { ok: false, skip: "privy_unavailable", detail: "unknown" };
        continue;
      }

      // ecrecover defense-in-depth.
      const recovered = await recoverTypedDataAddress({
        domain,
        types: LAZY_BET_TYPES,
        primaryType: "LazyBet",
        message: {
          user:       message.user,
          side:       sideEnum,
          amount:     BigInt(message.amount),
          closesAt:   BigInt(message.closesAt),
          entryPrice: BigInt(message.entryPrice),
          lazyNonce:  BigInt(message.lazyNonce),
          deadline:   BigInt(message.deadline),
        },
        signature,
      });
      if (recovered.toLowerCase() !== consent.wallet_address.toLowerCase()) {
        console.error("[autosign-take] SECURITY: recover mismatch", { recovered, expected: consent.wallet_address });
        return { ok: false, skip: "recover_mismatch", detail: recovered };
      }

      try {
        const result = await takeLazyMarket({
          pendingId:     input.pendingId,
          userId:        input.userId,
          walletAddress: consent.wallet_address,
          side:          takerSide,
          amountStr:     takerAmountStr,
          signature,
          lazyNonce,
          deadline,
        });
        if (attempt > 0) console.log(`[autosign-take] succeeded on attempt ${attempt + 1}/${MAX_ATTEMPTS}`);
        return { ok: true, pendingMarketId: result.pendingMarketId, symbol: pending.symbol, ca: pending.ca, chain: pending.chain, takerSide, amount: takerAmount };
      } catch (e: any) {
        if (e instanceof LazyOpenError) {
          if (e.code === "nonce_conflict") {
            lastResult = { ok: false, skip: "bet_rejected", detail: e.message };
            continue;
          }
          // not_pending / expired / own_market / same_side / insufficient / below_min → terminal
          if (["not_found", "not_pending", "expired", "own_market", "same_side"].includes(e.code)) {
            return { ok: false, skip: "take_unavailable", detail: e.code, terminal: true };
          }
          const skip: AutosignSkipReason = e.code === "insufficient" ? "no_balance" : "bet_rejected";
          lastResult = { ok: false, skip, detail: e.message, terminal: true };
          break;
        }
        console.error(`[autosign-take] attempt ${attempt + 1} takeLazyMarket unexpected:`, e);
        lastResult = { ok: false, skip: "bet_rejected", detail: e?.message ?? "unknown" };
        continue;
      }
    }
    return lastResult;
  } finally {
    if (lockHeld) {
      try { await client.query("SELECT pg_advisory_unlock($1)", [lockKey]); } catch {}
    }
    client.release();
  }
}

// ─── V5 queued bet autosign (bot bets on an EXISTING open market) ───────────
//
// Bot equivalent of POST /markets/:id/bet/queue. Bets on an already-live V5
// market via the BatchBet/placeBetsBatch rail. No advisory lock — the
// batchNonce is RESERVED atomically inside prepareQueuedBet. 2026-05-25.

export type AutosignQueuedBetInput = {
  userId:   string;
  username?: string;
  marketId: string;
  side:     "long" | "short";
  amount:   number;
  message?: string | null;
};

export type AutosignQueuedBetResult =
  | { ok: true; queueId: string; etaSeconds: number; side: "long" | "short"; amount: number }
  | { ok: false; skip: AutosignSkipReason | "market_unavailable"; detail?: string; terminal?: boolean };

export async function tryAutosignQueuedBet(input: AutosignQueuedBetInput): Promise<AutosignQueuedBetResult> {
  if (!AUTOSIGN_ENABLED) return { ok: false, skip: "feature_disabled" };
  const paused = tradingPausedSkip();
  if (paused) return paused;

  const consent = await getActiveConsent(input.userId);
  if (!consent) return { ok: false, skip: "no_consent" };
  if (!consent.privy_wallet_id) return { ok: false, skip: "no_privy_delegation", detail: "no wallet_id stored" };

  if (input.amount > HARD_CAP_PER_TRADE) {
    return { ok: false, skip: "hard_cap", detail: `>${HARD_CAP_PER_TRADE}`, terminal: true };
  }

  const balance = await checkVaultBalanceV5(input.userId);
  if (!balance.ok) {
    if (balance.reason === "rpc_error") return { ok: false, skip: "vault_rpc_error", detail: balance.reason };
    return { ok: false, skip: "no_wallet", detail: balance.reason, terminal: true };
  }
  if (balance.vault < input.amount) {
    return { ok: false, skip: "no_balance", detail: `need ${input.amount} have ${balance.vault}`, terminal: true };
  }
  if (balance.wallet.toLowerCase() !== consent.wallet_address.toLowerCase()) {
    return { ok: false, skip: "no_wallet", detail: "consent wallet mismatch", terminal: true };
  }

  const sideEnum  = input.side === "long" ? 0 : 1;
  const amountRaw = BigInt(Math.round(input.amount * 1e6)).toString();
  const domain    = buildLazyBetTypedDataDomain();

  // No advisory lock: prepareQueuedBet RESERVES a distinct batchNonce per call.
  // A transient Privy failure just re-prepares (fresh nonce; gaps harmless).
  const MAX_ATTEMPTS = 3;
  const BACKOFF_MS    = [0, 2_500, 5_000];
  let lastResult: AutosignQueuedBetResult = { ok: false, skip: "bet_rejected", detail: "no attempt run" };

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (BACKOFF_MS[attempt] > 0) await new Promise((r) => setTimeout(r, BACKOFF_MS[attempt]));

    let prep;
    try {
      prep = await prepareQueuedBet(input.userId, input.marketId);
    } catch (e: any) {
      if (e instanceof LazyOpenError) {
        // Market not open / not on-chain / closed / V4 → terminal.
        if (["not_found", "not_open", "not_onchain", "legacy_v4", "closed"].includes(e.code)) {
          return { ok: false, skip: "market_unavailable", detail: e.code, terminal: true };
        }
        if (e.code === "no_wallet") return { ok: false, skip: "no_wallet", detail: e.message, terminal: true };
      }
      lastResult = { ok: false, skip: "bet_rejected", detail: e?.message ?? String(e) };
      continue;
    }

    const message = {
      marketId:   String(prep.onchainMarketId),
      user:       consent.wallet_address as `0x${string}`,
      side:       sideEnum,
      amount:     amountRaw,
      batchNonce: prep.batchNonce,
      deadline:   String(prep.deadline),
    };

    let signature: `0x${string}`;
    try {
      signature = await signBatchBetTypedData({ walletId: consent.privy_wallet_id, domain, message });
    } catch (e: any) {
      if (e instanceof PrivyConfigError) return { ok: false, skip: "feature_disabled", detail: "no PRIVY_APP_SECRET" };
      if (e instanceof PrivyRpcError) {
        console.error(`[autosign-queue] attempt ${attempt + 1} Privy RPC ${e.status}:`, e.body);
        lastResult = { ok: false, skip: "privy_unavailable", detail: `${e.status}` };
        continue;
      }
      console.error(`[autosign-queue] attempt ${attempt + 1} Privy unexpected:`, e);
      lastResult = { ok: false, skip: "privy_unavailable", detail: "unknown" };
      continue;
    }

    // ecrecover defense-in-depth.
    const recovered = await recoverTypedDataAddress({
      domain,
      types: BATCH_BET_TYPES,
      primaryType: "BatchBet",
      message: {
        marketId:   BigInt(message.marketId),
        user:       message.user,
        side:       sideEnum,
        amount:     BigInt(message.amount),
        batchNonce: BigInt(message.batchNonce),
        deadline:   BigInt(message.deadline),
      },
      signature,
    });
    if (recovered.toLowerCase() !== consent.wallet_address.toLowerCase()) {
      console.error("[autosign-queue] SECURITY: recover mismatch", { recovered, expected: consent.wallet_address });
      return { ok: false, skip: "recover_mismatch", detail: recovered };
    }

    try {
      const result = await queueBet({
        userId:        input.userId,
        walletAddress: consent.wallet_address,
        marketId:      input.marketId,
        side:          input.side,
        amountStr:     String(input.amount),
        message:       input.message ?? null,
        signature,
        batchNonce:    prep.batchNonce,
        deadline:      prep.deadline,
      });
      if (attempt > 0) console.log(`[autosign-queue] succeeded on attempt ${attempt + 1}/${MAX_ATTEMPTS}`);
      return { ok: true, queueId: result.queueId, etaSeconds: result.etaSeconds, side: input.side, amount: input.amount };
    } catch (e: any) {
      if (e instanceof LazyOpenError) {
        // stale_nonce / dup_nonce → re-prepare + retry with a fresh nonce.
        if (e.code === "stale_nonce" || e.code === "dup_nonce") {
          lastResult = { ok: false, skip: "bet_rejected", detail: e.message };
          continue;
        }
        if (["not_found", "not_open", "not_onchain", "legacy_v4", "closed"].includes(e.code)) {
          return { ok: false, skip: "market_unavailable", detail: e.code, terminal: true };
        }
        const skip: AutosignSkipReason = e.code === "insufficient" ? "no_balance" : "bet_rejected";
        lastResult = { ok: false, skip, detail: e.message, terminal: true };
        break;
      }
      console.error(`[autosign-queue] attempt ${attempt + 1} queueBet unexpected:`, e);
      lastResult = { ok: false, skip: "bet_rejected", detail: e?.message ?? "unknown" };
      continue;
    }
  }
  return lastResult;
}
