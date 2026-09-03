import assert from "node:assert/strict";
import test from "node:test";
import { AgentGateway } from "../src/gateway.js";
import type { AgentIntent, ChannelEvent } from "../src/domain.js";

test("normalizes a channel command before calling FUDmarkets", async () => {
  const seen: Array<{ event: ChannelEvent; intent: AgentIntent }> = [];
  const gateway = new AgentGateway({
    async execute(event, intent) {
      seen.push({ event, intent });
      return { accepted: true, marketId: "market-1" };
    },
  });
  const event: ChannelEvent = {
    channel: "x",
    externalUserId: "x-user-42",
    sourceEventId: "x:tweet:123",
    text: "open BONK 24h short 5 thesis",
    privateChat: false,
    occurredAt: "2026-09-03T00:00:00.000Z",
  };
  const result = await gateway.handle(event);
  assert.equal(result.marketId, "market-1");
  assert.deepEqual(seen[0]?.intent, {
    kind: "market.open_with_position",
    token: "BONK",
    chain: "SOL",
    timeframe: "24h",
    side: "short",
    amountUsdc: 5,
    message: "thesis",
  });
});

