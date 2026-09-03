import assert from "node:assert/strict";
import test from "node:test";
import {
  AgenticAuthorizationError,
  authorizeAgenticCancelOrder,
  authorizeAgenticPlaceOrder,
  agenticOrderAuthorizationValueUsdcBaseUnits,
  type AgenticAuthorizationProvider,
  type AgenticGrant,
  type AgenticPlaceOrder,
  type VerifiedAgenticIntent,
} from "./agenticAuthorization.js";

const NOW = 1_800_000_000;
const USER = "11111111-1111-4111-8111-111111111111";
const MARKET = "22222222-2222-4222-8222-222222222222";

const order: AgenticPlaceOrder = {
  capability: "order.place",
  marketId: MARKET,
  assetSide: "long",
  action: "buy",
  limitPriceCents: 55,
  sharesCenti: 1_000,
  tif: "gtc",
  expiresAtSec: null,
  idempotencyKey: "x:tweet:123",
};

function grant(input: Partial<AgenticGrant> = {}): AgenticGrant {
  return {
    version: 1,
    id: "grant-1",
    provider: "magic",
    userId: USER,
    wallet: "magic-solana-wallet",
    chain: "solana",
    sessionDelegate: "magic-session-1",
    targetProgram: "fud-v2-vault",
    environment: "beta",
    audience: "fud-v2-order-engine",
    allowedChannels: ["x", "telegram"],
    allowedCapabilities: ["order.place", "order.cancel"],
    allowedMarketIds: [MARKET],
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 25_000_000,
    spentUsdcBaseUnits: 0,
    expiresAtSec: NOW + 3_600,
    revokedAtSec: null,
    ...input,
  };
}

function intent(input: Partial<VerifiedAgenticIntent> = {}): VerifiedAgenticIntent {
  const baseGrant = grant();
  return {
    grant: baseGrant,
    userId: USER,
    wallet: baseGrant.wallet,
    channel: "x",
    externalIdentity: "fud-user",
    sourceEventId: "x:tweet:123",
    nonce: "1",
    action: order,
    ...input,
  };
}

function provider(result: VerifiedAgenticIntent): AgenticAuthorizationProvider {
  return { verify: async () => result };
}

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

const options = {
  userId: USER,
  channel: "x" as const,
  externalIdentity: "fud-user",
  wallet: "magic-solana-wallet",
  provider: "magic",
  chain: "solana" as const,
  targetProgram: "fud-v2-vault",
  environment: "beta",
  audience: "fud-v2-order-engine",
  nowSec: NOW,
};

test("authorizes an exact provider-verified V2 order intent", async () => {
  const verified = await authorizeAgenticPlaceOrder(provider(intent()), {}, order, options);
  assert.equal(verified.userId, USER);
  assert.equal(agenticOrderAuthorizationValueUsdcBaseUnits(order), 5_550_000);
});

test("fails closed if any signed order field is changed", async () => {
  for (const changed of [
    { ...order, marketId: "other-market" },
    { ...order, assetSide: "short" as const },
    { ...order, action: "sell" as const },
    { ...order, limitPriceCents: 56 },
    { ...order, sharesCenti: 1_001 },
    { ...order, tif: "ioc" as const },
    { ...order, expiresAtSec: NOW + 60 },
    { ...order, idempotencyKey: "x:tweet:other" },
  ]) {
    await expectCode("intent_mismatch", () => (
      authorizeAgenticPlaceOrder(provider(intent()), {}, changed, options)
    ));
  }
});

test("rejects cross-user, cross-wallet and cross-environment execution", async () => {
  await expectCode("user_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ userId: "attacker" })), {}, order, options,
  ));
  await expectCode("wallet_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ wallet: "attacker-wallet" })), {}, order, options,
  ));
  await expectCode("external_identity_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ externalIdentity: "other-social-account" })), {}, order, options,
  ));
  await expectCode("channel_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ channel: "telegram" })), {}, order, options,
  ));
  await expectCode("target_program_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ targetProgram: "other-program" }) })), {}, order, options,
  ));
  await expectCode("provider_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ provider: "para" }) })), {}, order, options,
  ));
  await expectCode("environment_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ environment: "mainnet" }) })), {}, order, options,
  ));
  await expectCode("audience_mismatch", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ audience: "some-other-app" }) })), {}, order, options,
  ));
  await expectCode("channel_not_allowed", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ allowedChannels: ["telegram"] }) })), {}, order, options,
  ));
});

test("rejects forbidden market, missing scope, expiry and revocation", async () => {
  await expectCode("market_not_allowed", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ allowedMarketIds: ["other-market"] }) })), {}, order, options,
  ));
  await expectCode("capability_not_allowed", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ allowedCapabilities: ["order.cancel"] }) })), {}, order, options,
  ));
  await expectCode("grant_expired", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ expiresAtSec: NOW }) })), {}, order, options,
  ));
  await expectCode("grant_revoked", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ revokedAtSec: NOW - 1 }) })), {}, order, options,
  ));
  await expectCode("bad_grant_expiry", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ expiresAtSec: Number.POSITIVE_INFINITY }) })), {}, order, options,
  ));
  await expectCode("bad_grant_expiry", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ expiresAtSec: Number.NaN }) })), {}, order, options,
  ));
  await expectCode("bad_grant_market_scope", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ allowedMarketIds: "malformed" as never }) })), {}, order, options,
  ));
});

test("uses the engine's maximum BUY reservation for grant caps", async () => {
  const debit = agenticOrderAuthorizationValueUsdcBaseUnits(order);
  await expectCode("per_order_cap", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ maxPerOrderUsdcBaseUnits: debit - 1 }) })), {}, order, options,
  ));
  await expectCode("session_total_cap", () => authorizeAgenticPlaceOrder(
    provider(intent({ grant: grant({ spentUsdcBaseUnits: 20_000_000 }) })), {}, order, options,
  ));
});

test("caps SELL position value and rejects malformed order arithmetic", async () => {
  const sell = { ...order, action: "sell" as const, idempotencyKey: "telegram:sell:1" };
  const sellIntent = intent({ channel: "telegram", action: sell });
  const telegramOptions = { ...options, channel: "telegram" as const };
  assert.equal(agenticOrderAuthorizationValueUsdcBaseUnits(sell), 5_500_000);
  await expectCode("per_order_cap", () => authorizeAgenticPlaceOrder(
    provider({ ...sellIntent, grant: grant({ maxPerOrderUsdcBaseUnits: 5_499_999 }) }),
    {}, sell, telegramOptions,
  ));
  await expectCode("bad_order_amount", () => authorizeAgenticPlaceOrder(
    provider(intent({ action: { ...order, sharesCenti: 0 } })),
    {}, { ...order, sharesCenti: 0 }, options,
  ));
  await expectCode("bad_order_amount", () => authorizeAgenticPlaceOrder(
    provider(intent({ action: { ...order, limitPriceCents: 100 } })),
    {}, { ...order, limitPriceCents: 100 }, options,
  ));
});

test("cancel authorization is bound to one exact order", async () => {
  const cancel = {
    capability: "order.cancel" as const,
    marketId: MARKET,
    orderId: "33333333-3333-4333-8333-333333333333",
    idempotencyKey: "telegram:cancel:42",
  };
  const cancelIntent = intent({ channel: "telegram", action: cancel });
  const telegramOptions = { ...options, channel: "telegram" as const };
  await authorizeAgenticCancelOrder(provider(cancelIntent), {}, cancel, telegramOptions);
  await expectCode("intent_mismatch", () => authorizeAgenticCancelOrder(
    provider(cancelIntent), {}, { ...cancel, orderId: "other-order" }, telegramOptions,
  ));
  await expectCode("market_not_allowed", () => authorizeAgenticCancelOrder(
    provider({ ...cancelIntent, grant: grant({ allowedMarketIds: ["other-market"] }) }),
    {},
    cancel,
    telegramOptions,
  ));
});

test("provider errors propagate and cannot be interpreted as authorization", async () => {
  const failing: AgenticAuthorizationProvider = {
    verify: async () => { throw new Error("bad signature"); },
  };
  await assert.rejects(
    authorizeAgenticPlaceOrder(failing, {}, order, options),
    /bad signature/,
  );
});
