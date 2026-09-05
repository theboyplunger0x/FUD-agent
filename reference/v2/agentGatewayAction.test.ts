import assert from "node:assert/strict";
import test from "node:test";
import {
  AgentGatewayActionError,
  agenticActionFromGatewayIntent,
  centiSharesForAgentBudget,
} from "./agentGatewayAction.js";
import { agenticOrderAuthorizationValueUsdcBaseUnits } from "./agenticAuthorization.js";

test("turns an agent USDC budget into an exact capped V2 limit order", () => {
  const action = agenticActionFromGatewayIntent({
    channel: "x",
    sourceEventId: "x:tweet:123",
    intent: {
      kind: "order.place",
      marketId: "00000000-0000-4000-8000-000000000001",
      side: "long",
      amountUsdc: 10,
      maxPriceCents: 42,
    },
  });
  assert.equal(action.capability, "order.place");
  if (action.capability !== "order.place") throw new Error("bad action");
  assert.equal(action.limitPriceCents, 42);
  assert.equal(action.tif, "gtc");
  assert.ok(action.sharesCenti > 0);
  assert.ok(agenticOrderAuthorizationValueUsdcBaseUnits(action) <= 10_000_000);
  assert.equal(action.idempotencyKey.length, 70);
});

test("budget conversion finds the largest size including fee headroom", () => {
  const shares = centiSharesForAgentBudget(1, 50);
  assert.equal(shares, 198);
});

test("market opening fails closed until its atomic V2 capability exists", () => {
  assert.throws(() => agenticActionFromGatewayIntent({
    channel: "telegram",
    sourceEventId: "telegram:update:1",
    intent: {
      kind: "market.open_with_position",
      token: "SOL",
      chain: "SOL",
      timeframe: "6h",
      side: "long",
      amountUsdc: 5,
    },
  }), (error: unknown) => (
    error instanceof AgentGatewayActionError && error.code === "market_open_agentic_not_ready"
  ));
});

