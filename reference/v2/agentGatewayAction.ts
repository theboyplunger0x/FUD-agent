import { createHash } from "node:crypto";
import { MAX_SHARES_PER_ORDER } from "./config.js";
import type { AgenticV2Action } from "./agenticAuthorization.js";
import { costUsdc, takerFeeUsdc } from "./pricing.js";

export type AgentGatewayIntent =
  | {
      kind: "market.open_with_position";
      token: string;
      chain: "SOL";
      timeframe: "6h" | "12h" | "24h";
      side: "long" | "short";
      amountUsdc: number;
      message?: string;
    }
  | {
      kind: "order.place";
      marketId: string;
      side: "long" | "short";
      amountUsdc: number;
      maxPriceCents?: number;
    }
  | {
      kind: "order.cancel";
      marketId: string;
      orderId: string;
    };

export class AgentGatewayActionError extends Error {
  constructor(public readonly code: string, message = code) {
    super(message);
    this.name = "AgentGatewayActionError";
  }
}

function deterministicKey(channel: "x" | "telegram", sourceEventId: string): string {
  const digest = createHash("sha256")
    .update(`${channel}\0${sourceEventId}`)
    .digest("hex");
  return `agent:${digest}`;
}

function amountBaseUnits(amountUsdc: number): number {
  if (!Number.isFinite(amountUsdc) || amountUsdc <= 0 || amountUsdc > 100_000) {
    throw new AgentGatewayActionError("bad_amount");
  }
  const units = Math.round(amountUsdc * 1_000_000);
  if (!Number.isSafeInteger(units) || Math.abs(units / 1_000_000 - amountUsdc) > 1e-9) {
    throw new AgentGatewayActionError("bad_amount_precision");
  }
  return units;
}

/** Largest limit-order size whose reservation + worst-case fee fits the user's budget. */
export function centiSharesForAgentBudget(amountUsdc: number, priceCents: number): number {
  const budget = amountBaseUnits(amountUsdc);
  if (!Number.isInteger(priceCents) || priceCents < 1 || priceCents > 99) {
    throw new AgentGatewayActionError("bad_price");
  }
  let low = 0;
  let high = Math.min(MAX_SHARES_PER_ORDER, Math.floor(budget / (priceCents * 100)));
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    const authorization = costUsdc(middle, priceCents) + takerFeeUsdc(middle, 50);
    if (authorization <= budget) low = middle;
    else high = middle - 1;
  }
  if (low < 1) throw new AgentGatewayActionError("amount_below_minimum_share");
  return low;
}

export function agenticActionFromGatewayIntent(input: {
  channel: "x" | "telegram";
  sourceEventId: string;
  intent: AgentGatewayIntent;
}): AgenticV2Action {
  const idempotencyKey = deterministicKey(input.channel, input.sourceEventId);
  if (input.intent.kind === "market.open_with_position") {
    // Market creation needs one atomic grant-consumption + create + opener-order
    // receipt. It is intentionally rejected until that engine capability lands.
    throw new AgentGatewayActionError(
      "market_open_agentic_not_ready",
      "Agentic market opening is not connected yet; normal V2 market creation remains available.",
    );
  }
  if (input.intent.kind === "order.cancel") {
    return {
      capability: "order.cancel",
      marketId: input.intent.marketId,
      orderId: input.intent.orderId,
      idempotencyKey,
    };
  }
  const limitPriceCents = input.intent.maxPriceCents ?? 50;
  return {
    capability: "order.place",
    marketId: input.intent.marketId,
    assetSide: input.intent.side,
    action: "buy",
    limitPriceCents,
    sharesCenti: centiSharesForAgentBudget(input.intent.amountUsdc, limitPriceCents),
    tif: "gtc",
    expiresAtSec: null,
    idempotencyKey,
  };
}

