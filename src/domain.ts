export type AgentChannel = "telegram" | "x";
export type MarketSide = "long" | "short";
export type MarketTimeframe = "6h" | "12h" | "24h";

export type ChannelEvent = {
  channel: AgentChannel;
  externalUserId: string;
  sourceEventId: string;
  text: string;
  privateChat: boolean;
  occurredAt: string;
};

export type OpenMarketIntent = {
  kind: "market.open_with_position";
  token: string;
  chain: "SOL";
  timeframe: MarketTimeframe;
  side: MarketSide;
  amountUsdc: number;
  message?: string;
};

export type PlaceOrderIntent = {
  kind: "order.place";
  marketId: string;
  side: MarketSide;
  amountUsdc: number;
  maxPriceCents?: number;
};

export type CancelOrderIntent = {
  kind: "order.cancel";
  marketId: string;
  orderId: string;
};

export type AgentIntent = OpenMarketIntent | PlaceOrderIntent | CancelOrderIntent;

export class IntentParseError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
  }
}

function positiveAmount(raw: string): number {
  const amount = Number(raw.replace(/^\$/, ""));
  if (!Number.isFinite(amount) || amount <= 0 || amount > 100_000) {
    throw new IntentParseError("bad_amount", "Amount must be a positive USDC value");
  }
  return amount;
}

function side(raw: string): MarketSide {
  const normalized = raw.toLowerCase();
  if (normalized !== "long" && normalized !== "short") {
    throw new IntentParseError("bad_side", "Side must be LONG or SHORT");
  }
  return normalized;
}

function timeframe(raw: string): MarketTimeframe {
  const normalized = raw.toLowerCase();
  if (normalized !== "6h" && normalized !== "12h" && normalized !== "24h") {
    throw new IntentParseError("bad_timeframe", "Timeframe must be 6h, 12h or 24h");
  }
  return normalized;
}

/**
 * Deterministic command parser used before any optional LLM interpretation.
 * An LLM may propose one of these commands, but only this strict parser creates
 * a value-moving intent.
 *
 *   open $BONK 6h long $25 optional thesis
 *   buy <market-id> short $10 max 42c
 *   cancel <market-id> <order-id>
 */
export function parseCommand(input: string): AgentIntent {
  const text = input.trim();
  const open = text.match(/^open\s+(\$?[A-Za-z0-9._:-]{1,64})\s+(6h|12h|24h)\s+(long|short)\s+\$?([0-9]+(?:\.[0-9]{1,2})?)(?:\s+(.{1,140}))?$/i);
  if (open) {
    const token = open[1];
    const tf = open[2];
    const rawSide = open[3];
    const rawAmount = open[4];
    if (!token || !tf || !rawSide || !rawAmount) throw new IntentParseError("bad_open", "Invalid open command");
    const message = open[5]?.trim();
    return {
      kind: "market.open_with_position",
      token: token.replace(/^\$/, "").toUpperCase(),
      chain: "SOL",
      timeframe: timeframe(tf),
      side: side(rawSide),
      amountUsdc: positiveAmount(rawAmount),
      ...(message ? { message } : {}),
    };
  }

  const buy = text.match(/^buy\s+([A-Za-z0-9-]{8,64})\s+(long|short)\s+\$?([0-9]+(?:\.[0-9]{1,2})?)(?:\s+max\s+([0-9]{1,2})c)?$/i);
  if (buy) {
    const marketId = buy[1];
    const rawSide = buy[2];
    const rawAmount = buy[3];
    if (!marketId || !rawSide || !rawAmount) throw new IntentParseError("bad_buy", "Invalid buy command");
    const maxPriceCents = buy[4] === undefined ? undefined : Number(buy[4]);
    if (maxPriceCents !== undefined && (maxPriceCents < 1 || maxPriceCents > 99)) {
      throw new IntentParseError("bad_price", "Maximum share price must be 1c to 99c");
    }
    return {
      kind: "order.place",
      marketId,
      side: side(rawSide),
      amountUsdc: positiveAmount(rawAmount),
      ...(maxPriceCents === undefined ? {} : { maxPriceCents }),
    };
  }

  const cancel = text.match(/^cancel\s+([A-Za-z0-9-]{8,64})\s+([A-Za-z0-9-]{8,64})$/i);
  if (cancel) {
    const marketId = cancel[1];
    const orderId = cancel[2];
    if (!marketId || !orderId) throw new IntentParseError("bad_cancel", "Invalid cancel command");
    return { kind: "order.cancel", marketId, orderId };
  }

  throw new IntentParseError("unsupported_command", "Supported commands: open, buy and cancel");
}

export function validateChannelEvent(event: ChannelEvent): void {
  if (!event.externalUserId.trim() || event.externalUserId.length > 256) {
    throw new IntentParseError("bad_external_user", "Invalid external user identity");
  }
  if (!event.sourceEventId.trim() || event.sourceEventId.length > 256) {
    throw new IntentParseError("bad_source_event", "Invalid source event identity");
  }
  if (!event.text.trim() || event.text.length > 2_000) {
    throw new IntentParseError("bad_text", "Invalid command text");
  }
  if (event.channel === "telegram" && !event.privateChat) {
    throw new IntentParseError("telegram_dm_required", "Value-moving Telegram actions require a private chat");
  }
  if (event.channel === "x" && !event.sourceEventId.startsWith("x:")) {
    throw new IntentParseError("bad_x_event", "X events require a canonical x: source event id");
  }
}

