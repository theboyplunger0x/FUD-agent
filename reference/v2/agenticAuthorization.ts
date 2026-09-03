import type { Action, Side, TimeInForce } from "./types.js";
import { MAX_SHARES_PER_ORDER } from "./config.js";
import { costUsdc, isValidPriceCents, takerFeeUsdc } from "./pricing.js";

export type AgenticChannel = "x" | "telegram";
export type AgenticCapability = "order.place" | "order.cancel";

export type AgenticPlaceOrder = {
  capability: "order.place";
  marketId: string;
  assetSide: Side;
  action: Action;
  limitPriceCents: number;
  sharesCenti: number;
  tif: TimeInForce;
  expiresAtSec: number | null;
  idempotencyKey: string;
};

export type AgenticCancelOrder = {
  capability: "order.cancel";
  marketId: string;
  orderId: string;
  idempotencyKey: string;
};

export type AgenticV2Action = AgenticPlaceOrder | AgenticCancelOrder;

/**
 * This grant is product policy, not a wallet-vendor object. Magic, Para or a
 * future session-key verifier must all return this same normalized shape.
 */
export interface AgenticGrant {
  version: 1;
  id: string;
  provider: string;
  userId: string;
  wallet: string;
  chain: "solana";
  sessionDelegate: string;
  targetProgram: string;
  environment: string;
  audience: string;
  allowedChannels: readonly AgenticChannel[];
  allowedCapabilities: readonly AgenticCapability[];
  /** null means any currently tradeable market, still subject to V2 guards. */
  allowedMarketIds: readonly string[] | null;
  maxPerOrderUsdcBaseUnits: number;
  maxTotalUsdcBaseUnits: number;
  spentUsdcBaseUnits: number;
  expiresAtSec: number;
  revokedAtSec: number | null;
}

export interface VerifiedAgenticIntent {
  grant: AgenticGrant;
  userId: string;
  wallet: string;
  channel: AgenticChannel;
  externalIdentity: string;
  sourceEventId: string;
  nonce: string;
  action: AgenticV2Action;
}

/** Wallet/provider-specific code only verifies the credential and normalizes it. */
export interface AgenticAuthorizationProvider {
  verify(envelope: unknown): Promise<VerifiedAgenticIntent>;
}

export class AgenticAuthorizationError extends Error {
  constructor(public readonly code: string, message = code) {
    super(message);
    this.name = "AgenticAuthorizationError";
  }
}

function requireSafeNonNegative(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new AgenticAuthorizationError(code);
}

function requireNonEmpty(value: string, code: string): void {
  if (!value.trim()) throw new AgenticAuthorizationError(code);
}

function sameStringSetValue(values: readonly string[] | null, expected: string): boolean {
  return values === null || values.includes(expected);
}

function requireStringArray(
  value: readonly string[],
  allowed: ReadonlySet<string> | null,
  code: string,
): void {
  if (!Array.isArray(value)
      || value.some((entry) => typeof entry !== "string" || !entry.trim() || (allowed && !allowed.has(entry)))) {
    throw new AgenticAuthorizationError(code);
  }
}

/**
 * Matches the maximum BUY reservation used by placeV2Order: notional at the
 * user's limit plus worst-case taker-fee headroom. SELL orders debit no USDC.
 */
export function agenticOrderAuthorizationValueUsdcBaseUnits(action: AgenticPlaceOrder): number {
  if (!isValidPriceCents(action.limitPriceCents)
      || !Number.isSafeInteger(action.sharesCenti)
      || action.sharesCenti <= 0
      || action.sharesCenti > MAX_SHARES_PER_ORDER) {
    throw new AgenticAuthorizationError("bad_order_amount");
  }
  const notional = costUsdc(action.sharesCenti, action.limitPriceCents);
  // A buy can debit the reservation plus fee headroom. A sell moves an owned
  // position rather than USDC, so its own-side notional is the authorization
  // value used by the same grant caps.
  const authorizationValue = action.action === "buy"
    ? notional + takerFeeUsdc(action.sharesCenti, 50)
    : notional;
  if (!Number.isSafeInteger(authorizationValue) || authorizationValue < 0) {
    throw new AgenticAuthorizationError("unsafe_order_debit");
  }
  return authorizationValue;
}

function validateCommon(
  intent: VerifiedAgenticIntent,
  expected: {
    userId: string;
    channel: AgenticChannel;
    externalIdentity: string;
    wallet: string;
    provider: string;
    chain: "solana";
    targetProgram: string;
    environment: string;
    audience: string;
  },
  nowSec: number,
): void {
  requireNonEmpty(intent.sourceEventId, "missing_source_event");
  requireNonEmpty(intent.nonce, "missing_nonce");
  requireNonEmpty(intent.wallet, "missing_wallet");
  requireNonEmpty(intent.externalIdentity, "missing_external_identity");
  requireNonEmpty(intent.action.idempotencyKey, "missing_idempotency_key");
  if (intent.action.idempotencyKey.length > 128
      || intent.action.idempotencyKey.trim() !== intent.action.idempotencyKey) {
    throw new AgenticAuthorizationError("bad_idempotency_key");
  }
  requireNonEmpty(expected.wallet, "missing_expected_wallet");
  requireNonEmpty(expected.provider, "missing_expected_provider");
  requireSafeNonNegative(nowSec, "bad_now");

  const { grant } = intent;
  if (grant.version !== 1) throw new AgenticAuthorizationError("unsupported_grant_version");
  requireNonEmpty(grant.id, "missing_grant_id");
  requireNonEmpty(grant.provider, "missing_provider");
  requireNonEmpty(grant.sessionDelegate, "missing_session_delegate");
  requireNonEmpty(grant.targetProgram, "missing_target_program");
  if (intent.userId !== expected.userId || grant.userId !== expected.userId) {
    throw new AgenticAuthorizationError("user_mismatch");
  }
  if (intent.externalIdentity !== expected.externalIdentity) {
    throw new AgenticAuthorizationError("external_identity_mismatch");
  }
  if (intent.channel !== expected.channel) {
    throw new AgenticAuthorizationError("channel_mismatch");
  }
  if (grant.provider !== expected.provider) throw new AgenticAuthorizationError("provider_mismatch");
  if (intent.wallet !== grant.wallet || grant.wallet !== expected.wallet) {
    throw new AgenticAuthorizationError("wallet_mismatch");
  }
  if (grant.chain !== expected.chain) throw new AgenticAuthorizationError("chain_mismatch");
  if (grant.targetProgram !== expected.targetProgram) {
    throw new AgenticAuthorizationError("target_program_mismatch");
  }
  if (grant.environment !== expected.environment) {
    throw new AgenticAuthorizationError("environment_mismatch");
  }
  if (grant.audience !== expected.audience) throw new AgenticAuthorizationError("audience_mismatch");
  requireStringArray(grant.allowedChannels, new Set<AgenticChannel>(["x", "telegram"]), "bad_grant_channels");
  requireStringArray(
    grant.allowedCapabilities,
    new Set<AgenticCapability>(["order.place", "order.cancel"]),
    "bad_grant_capabilities",
  );
  if (grant.allowedMarketIds !== null) {
    requireStringArray(grant.allowedMarketIds, null, "bad_grant_market_scope");
  }
  if (!grant.allowedChannels.includes(intent.channel)) {
    throw new AgenticAuthorizationError("channel_not_allowed");
  }
  if (!Number.isSafeInteger(grant.expiresAtSec) || grant.expiresAtSec <= 0) {
    throw new AgenticAuthorizationError("bad_grant_expiry");
  }
  if (grant.revokedAtSec !== null
      && (!Number.isSafeInteger(grant.revokedAtSec) || grant.revokedAtSec < 0)) {
    throw new AgenticAuthorizationError("bad_grant_revocation");
  }
  if (grant.revokedAtSec !== null) throw new AgenticAuthorizationError("grant_revoked");
  if (grant.expiresAtSec <= nowSec) throw new AgenticAuthorizationError("grant_expired");
  if (!grant.allowedCapabilities.includes(intent.action.capability)) {
    throw new AgenticAuthorizationError("capability_not_allowed");
  }
  requireSafeNonNegative(grant.maxPerOrderUsdcBaseUnits, "bad_grant_limit");
  requireSafeNonNegative(grant.maxTotalUsdcBaseUnits, "bad_grant_limit");
  requireSafeNonNegative(grant.spentUsdcBaseUnits, "bad_grant_spend");
  if (grant.spentUsdcBaseUnits > grant.maxTotalUsdcBaseUnits) {
    throw new AgenticAuthorizationError("bad_grant_spend");
  }
}

function samePlaceOrder(a: AgenticPlaceOrder, b: AgenticPlaceOrder): boolean {
  return a.marketId === b.marketId
    && a.assetSide === b.assetSide
    && a.action === b.action
    && a.limitPriceCents === b.limitPriceCents
    && a.sharesCenti === b.sharesCenti
    && a.tif === b.tif
    && a.expiresAtSec === b.expiresAtSec
    && a.idempotencyKey === b.idempotencyKey;
}

/**
 * Verify an exact, signed order intent before the caller opens a DB
 * transaction. Nonce/source-event consumption and cumulative-spend mutation
 * must still happen atomically in that same transaction as placeV2Order.
 */
export async function authorizeAgenticPlaceOrder(
  provider: AgenticAuthorizationProvider,
  envelope: unknown,
  expected: AgenticPlaceOrder,
  options: {
    userId: string;
    channel: AgenticChannel;
    externalIdentity: string;
    wallet: string;
    provider: string;
    chain: "solana";
    targetProgram: string;
    environment: string;
    audience: string;
    nowSec: number;
  },
): Promise<VerifiedAgenticIntent> {
  const intent = await provider.verify(envelope);
  validateCommon(intent, options, options.nowSec);
  if (intent.action.capability !== "order.place") {
    throw new AgenticAuthorizationError("wrong_capability");
  }
  if (!samePlaceOrder(intent.action, expected)) {
    throw new AgenticAuthorizationError("intent_mismatch");
  }
  if (!sameStringSetValue(intent.grant.allowedMarketIds, expected.marketId)) {
    throw new AgenticAuthorizationError("market_not_allowed");
  }
  const authorizationValue = agenticOrderAuthorizationValueUsdcBaseUnits(expected);
  if (authorizationValue > intent.grant.maxPerOrderUsdcBaseUnits) {
    throw new AgenticAuthorizationError("per_order_cap");
  }
  const nextSpend = intent.grant.spentUsdcBaseUnits + authorizationValue;
  if (!Number.isSafeInteger(nextSpend)) throw new AgenticAuthorizationError("unsafe_session_spend");
  if (nextSpend > intent.grant.maxTotalUsdcBaseUnits) {
    throw new AgenticAuthorizationError("session_total_cap");
  }
  return intent;
}

export async function authorizeAgenticCancelOrder(
  provider: AgenticAuthorizationProvider,
  envelope: unknown,
  expected: AgenticCancelOrder,
  options: {
    userId: string;
    channel: AgenticChannel;
    externalIdentity: string;
    wallet: string;
    provider: string;
    chain: "solana";
    targetProgram: string;
    environment: string;
    audience: string;
    nowSec: number;
  },
): Promise<VerifiedAgenticIntent> {
  const intent = await provider.verify(envelope);
  validateCommon(intent, options, options.nowSec);
  if (intent.action.capability !== "order.cancel") {
    throw new AgenticAuthorizationError("wrong_capability");
  }
  if (intent.action.orderId !== expected.orderId
      || intent.action.marketId !== expected.marketId
      || intent.action.idempotencyKey !== expected.idempotencyKey) {
    throw new AgenticAuthorizationError("intent_mismatch");
  }
  if (!sameStringSetValue(intent.grant.allowedMarketIds, expected.marketId)) {
    throw new AgenticAuthorizationError("market_not_allowed");
  }
  return intent;
}
