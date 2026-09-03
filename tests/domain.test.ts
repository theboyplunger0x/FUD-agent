import assert from "node:assert/strict";
import test from "node:test";
import { parseCommand, validateChannelEvent } from "../src/domain.js";

test("parses a Solana market open with the frozen product timeframes", () => {
  assert.deepEqual(parseCommand("open $bonk 6h long $25 breakout incoming"), {
    kind: "market.open_with_position",
    token: "BONK",
    chain: "SOL",
    timeframe: "6h",
    side: "long",
    amountUsdc: 25,
    message: "breakout incoming",
  });
});

test("parses an order with an explicit share-price ceiling", () => {
  assert.deepEqual(parseCommand("buy 12345678-abcd short 10 max 42c"), {
    kind: "order.place",
    marketId: "12345678-abcd",
    side: "short",
    amountUsdc: 10,
    maxPriceCents: 42,
  });
});

test("parses cancellation", () => {
  assert.deepEqual(parseCommand("cancel market-123 order-456"), {
    kind: "order.cancel",
    marketId: "market-123",
    orderId: "order-456",
  });
});

test("rejects deprecated or unsupported timeframes", () => {
  assert.throws(() => parseCommand("open SOL 1h long 25"), /Supported commands/);
});

test("Telegram value movement requires a private chat", () => {
  assert.throws(() => validateChannelEvent({
    channel: "telegram",
    externalUserId: "123",
    sourceEventId: "telegram:update:9",
    text: "open SOL 6h long 25",
    privateChat: false,
    occurredAt: new Date(0).toISOString(),
  }), /private chat/);
});

