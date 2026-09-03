import { randomUUID } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import type { SolanaAgenticGrantDefinitionV1 } from "./solanaAgenticProvider.js";

const DEFAULT_PER_ORDER_USDC = 25_000_000; // $25
const DEFAULT_TOTAL_USDC = 100_000_000; // $100 per grant
const DEFAULT_TTL_SECONDS = 24 * 60 * 60;

function positiveSafeInteger(raw: string | undefined, fallback: number, name: string): number {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function canonicalPublicKey(raw: string | undefined, name: string): string {
  if (!raw?.trim()) throw new Error(`${name} is required`);
  const key = new PublicKey(raw.trim());
  if (key.toBase58() !== raw.trim()) throw new Error(`${name} must be canonical base58`);
  return key.toBase58();
}

export type AgenticConsentPolicy = {
  targetProgram: string;
  environment: string;
  audience: string;
  maxPerOrderUsdcBaseUnits: number;
  maxTotalUsdcBaseUnits: number;
  ttlSeconds: number;
};

export function agenticConsentPolicy(
  env: NodeJS.ProcessEnv = process.env,
  environment: string,
): AgenticConsentPolicy {
  const maxPerOrderUsdcBaseUnits = positiveSafeInteger(
    env.FUDV2_AGENTIC_MAX_PER_ORDER_USDC_BASE_UNITS,
    DEFAULT_PER_ORDER_USDC,
    "FUDV2_AGENTIC_MAX_PER_ORDER_USDC_BASE_UNITS",
  );
  const maxTotalUsdcBaseUnits = positiveSafeInteger(
    env.FUDV2_AGENTIC_MAX_TOTAL_USDC_BASE_UNITS,
    DEFAULT_TOTAL_USDC,
    "FUDV2_AGENTIC_MAX_TOTAL_USDC_BASE_UNITS",
  );
  if (maxPerOrderUsdcBaseUnits > maxTotalUsdcBaseUnits) {
    throw new Error("agentic per-order limit cannot exceed total limit");
  }
  return {
    targetProgram: canonicalPublicKey(env.V2_SOLANA_PROGRAM_ID, "V2_SOLANA_PROGRAM_ID"),
    environment,
    audience: env.FUDV2_AGENTIC_AUDIENCE?.trim() || "fud-v2-order-engine",
    maxPerOrderUsdcBaseUnits,
    maxTotalUsdcBaseUnits,
    ttlSeconds: positiveSafeInteger(
      env.FUDV2_AGENTIC_GRANT_TTL_SECONDS,
      DEFAULT_TTL_SECONDS,
      "FUDV2_AGENTIC_GRANT_TTL_SECONDS",
    ),
  };
}

export function prepareAgenticGrant(input: {
  userId: string;
  wallet: string;
  sessionDelegate: string;
  policy: AgenticConsentPolicy;
  nowSec: number;
  id?: string;
}): SolanaAgenticGrantDefinitionV1 {
  if (!Number.isSafeInteger(input.nowSec) || input.nowSec <= 0) {
    throw new AgenticAuthorizationError("bad_now");
  }
  return {
    version: 1,
    id: input.id ?? randomUUID(),
    provider: "magic",
    userId: input.userId,
    wallet: canonicalPublicKey(input.wallet, "wallet"),
    chain: "solana",
    sessionDelegate: canonicalPublicKey(input.sessionDelegate, "sessionDelegate"),
    targetProgram: input.policy.targetProgram,
    environment: input.policy.environment,
    audience: input.policy.audience,
    allowedChannels: ["x", "telegram"],
    allowedCapabilities: ["order.place", "order.cancel"],
    allowedMarketIds: null,
    maxPerOrderUsdcBaseUnits: input.policy.maxPerOrderUsdcBaseUnits,
    maxTotalUsdcBaseUnits: input.policy.maxTotalUsdcBaseUnits,
    expiresAtSec: input.nowSec + input.policy.ttlSeconds,
  };
}

function exactArray(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

/** Rebuild the server policy around client-variable id/expiry and compare every field. */
export function assertAgenticGrantMatchesConsent(input: {
  grant: SolanaAgenticGrantDefinitionV1;
  userId: string;
  wallet: string;
  sessionDelegate: string;
  policy: AgenticConsentPolicy;
  nowSec: number;
}): void {
  const { grant, policy } = input;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(grant.id)) {
    throw new AgenticAuthorizationError("bad_grant_id");
  }
  if (grant.provider !== "magic"
      || grant.userId !== input.userId
      || grant.wallet !== input.wallet
      || grant.chain !== "solana"
      || grant.sessionDelegate !== input.sessionDelegate
      || grant.targetProgram !== policy.targetProgram
      || grant.environment !== policy.environment
      || grant.audience !== policy.audience
      || !exactArray(grant.allowedChannels, ["x", "telegram"])
      || !exactArray(grant.allowedCapabilities, ["order.place", "order.cancel"])
      || grant.allowedMarketIds !== null
      || grant.maxPerOrderUsdcBaseUnits !== policy.maxPerOrderUsdcBaseUnits
      || grant.maxTotalUsdcBaseUnits !== policy.maxTotalUsdcBaseUnits) {
    throw new AgenticAuthorizationError("grant_policy_mismatch");
  }
  if (!Number.isSafeInteger(grant.expiresAtSec)
      || grant.expiresAtSec <= input.nowSec
      || grant.expiresAtSec > input.nowSec + policy.ttlSeconds) {
    throw new AgenticAuthorizationError("grant_expiry_out_of_policy");
  }
}
