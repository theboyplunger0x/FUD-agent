import assert from "node:assert/strict";
import test from "node:test";
import {
  AgenticAuthorizationError,
  authorizeAgenticCancelOrder,
  authorizeAgenticPlaceOrder,
  type AgenticAuthorizationProvider,
  type AgenticGrant,
  type AgenticPlaceOrder,
  type VerifiedAgenticIntent,
} from "./agenticAuthorization.js";
import {
  activateExclusiveAgenticGrantInTransaction,
  loadActiveAgenticGrantMaterial,
  persistAgenticGrant,
  revokeAllAgenticGrantsForUserInTransaction,
  revokeAgenticGrant,
} from "./agenticGrantStore.js";
import { cancelV2Order, placeV2Order } from "./executor.js";
import { createMarket, createUser, makeTestDb } from "./testdb.js";

const TARGET_PROGRAM = "fud-v2-solana-vault";
const AUDIENCE = "fud-v2-order-engine";

function provider(intent: VerifiedAgenticIntent): AgenticAuthorizationProvider {
  return { verify: async () => intent };
}

function grant(userId: string, marketId: string, expiresAtSec: number): AgenticGrant {
  return {
    version: 1,
    id: `grant:${userId}`,
    provider: "magic",
    userId,
    wallet: `solana-wallet:${userId}`,
    chain: "solana",
    sessionDelegate: `delegate:${userId}`,
    targetProgram: TARGET_PROGRAM,
    environment: "test",
    audience: AUDIENCE,
    allowedChannels: ["x", "telegram"],
    allowedCapabilities: ["order.place", "order.cancel"],
    allowedMarketIds: [marketId],
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 20_000_000,
    spentUsdcBaseUnits: 0,
    expiresAtSec,
    revokedAtSec: null,
  };
}

function placeAction(marketId: string, idempotencyKey = "x:post:101"): AgenticPlaceOrder {
  return {
    capability: "order.place",
    marketId,
    assetSide: "long",
    action: "buy",
    limitPriceCents: 55,
    sharesCenti: 1_000,
    tif: "gtc",
    expiresAtSec: null,
    idempotencyKey,
  };
}

function intentFor(grantValue: AgenticGrant, action: VerifiedAgenticIntent["action"], overrides: Partial<VerifiedAgenticIntent> = {}): VerifiedAgenticIntent {
  return {
    grant: grantValue,
    userId: grantValue.userId,
    wallet: grantValue.wallet,
    channel: "x",
    externalIdentity: "x:user:42",
    sourceEventId: action.idempotencyKey,
    nonce: "nonce:1",
    action,
    ...overrides,
  };
}

function authOptions(grantValue: AgenticGrant, nowSec: number) {
  return {
    userId: grantValue.userId,
    channel: "x" as const,
    externalIdentity: "x:user:42",
    wallet: grantValue.wallet,
    provider: grantValue.provider,
    chain: "solana" as const,
    targetProgram: TARGET_PROGRAM,
    environment: "test",
    audience: AUDIENCE,
    nowSec,
  };
}

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

test("agentic placement consumes grant and creates its receipt in the order transaction", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-place", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const grantValue = grant(userId, marketId, nowSec + 1_800);
  await persistAgenticGrant(db, grantValue);
  const action = placeAction(marketId);
  const verified = await authorizeAgenticPlaceOrder(
    provider(intentFor(grantValue, action)),
    {},
    action,
    authOptions(grantValue, nowSec),
  );

  const first = await placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: verified,
  });
  assert.equal(first.status, "open");

  const state = await db.query<{ spent: string; uses: string; order_id: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses,
            (array_agg(c.order_id) FILTER (WHERE c.order_id IS NOT NULL))[1]::text AS order_id
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [grantValue.id],
  );
  assert.equal(state.rows[0].spent, "5550000");
  assert.equal(state.rows[0].uses, "1");
  assert.equal(state.rows[0].order_id, first.orderId);

  const replay = await placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: verified,
  });
  assert.equal(replay.orderId, first.orderId);
  assert.equal(replay.idempotentReplay, true);
  assert.equal(replay.takerRemainingCenti, action.sharesCenti);
  const replayState = await db.query<{ spent: string; uses: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [grantValue.id],
  );
  assert.deepEqual(replayState.rows[0], { spent: "5550000", uses: "1" });
});

test("failed order rolls back nonce, source event and cumulative grant use", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-no-funds", "0");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const grantValue = grant(userId, marketId, nowSec + 1_800);
  await persistAgenticGrant(db, grantValue);
  const action = placeAction(marketId);
  const verified = intentFor(grantValue, action);

  await assert.rejects(() => placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: verified,
  }), /insufficient balance/);

  const state = await db.query<{ spent: string; uses: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [grantValue.id],
  );
  assert.deepEqual(state.rows[0], { spent: "0", uses: "0" });
});

test("authoritative DB revocation rejects a stale still-active envelope", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-revoked", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const grantValue = grant(userId, marketId, nowSec + 1_800);
  await persistAgenticGrant(db, grantValue);
  await revokeAgenticGrant(db, grantValue.id, nowSec);
  const action = placeAction(marketId);

  await expectCode("grant_revoked", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: intentFor(grantValue, action),
  }));
});

test("activating a new grant atomically revokes every older active grant", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-exclusive", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const first = grant(userId, marketId, nowSec + 1_800);
  const second = { ...first, id: `grant:replacement:${userId}` };

  await db.query("BEGIN");
  await activateExclusiveAgenticGrantInTransaction(db, first);
  await db.query("COMMIT");
  await db.query("BEGIN");
  await activateExclusiveAgenticGrantInTransaction(db, second);
  await db.query("COMMIT");

  const rows = await db.query<{ id: string; active: boolean }>(
    `SELECT id,(revoked_at IS NULL) AS active
       FROM v2_agentic_grants WHERE user_id=$1::uuid ORDER BY id`,
    [userId],
  );
  assert.deepEqual(rows.rows, [
    { id: first.id, active: false },
    { id: second.id, active: true },
  ]);
});

test("social gateway loads only a signed active grant and returns its immutable definition", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-material", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const active = grant(userId, marketId, nowSec + 1_800);

  await db.query("BEGIN");
  await activateExclusiveAgenticGrantInTransaction(db, active);
  await db.query("COMMIT");
  await expectCode("grant_signature_not_stored", () => (
    loadActiveAgenticGrantMaterial(db, userId)
  ));

  await db.query(
    "UPDATE v2_agentic_grants SET wallet_grant_signature=$2 WHERE id=$1",
    [active.id, "signed-by-user-wallet"],
  );
  const material = await loadActiveAgenticGrantMaterial(db, userId);
  assert.equal(material.grantSignature, "signed-by-user-wallet");
  assert.equal(material.grant.id, active.id);
  assert.equal(material.grant.userId, userId);
  assert.deepEqual(material.grant.allowedCapabilities, ["order.place", "order.cancel"]);
  assert.equal("spentUsdcBaseUnits" in material.grant, false);
  assert.equal("revokedAtSec" in material.grant, false);
});

test("revoke-all shares the activation lock and revokes the current provider grant", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-revoke-all", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const active = grant(userId, marketId, nowSec + 1_800);

  await db.query("BEGIN");
  await activateExclusiveAgenticGrantInTransaction(db, active);
  await db.query("COMMIT");
  await db.query("BEGIN");
  await revokeAllAgenticGrantsForUserInTransaction(db, userId, "magic");
  await db.query("COMMIT");

  const rows = await db.query<{ id: string; active: boolean }>(
    `SELECT id,(revoked_at IS NULL) AS active
       FROM v2_agentic_grants WHERE user_id=$1::uuid ORDER BY id`,
    [userId],
  );
  assert.deepEqual(rows.rows, [{ id: active.id, active: false }]);
});

test("per-order and cumulative caps reject without consuming grant state", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-caps", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const tooSmallPerOrder = {
    ...grant(userId, marketId, nowSec + 1_800),
    id: `grant:per-order:${userId}`,
    maxPerOrderUsdcBaseUnits: 5_000_000,
  };
  await persistAgenticGrant(db, tooSmallPerOrder);
  const firstAction = placeAction(marketId, "x:post:cap-per-order");

  await expectCode("per_order_cap", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: firstAction.assetSide,
    action: firstAction.action,
    limitPriceCents: firstAction.limitPriceCents,
    sharesCenti: firstAction.sharesCenti,
    tif: firstAction.tif,
    expiresAtSec: firstAction.expiresAtSec,
    idempotencyKey: firstAction.idempotencyKey,
    agenticIntent: intentFor(tooSmallPerOrder, firstAction),
  }));
  const perOrderState = await db.query<{ spent: string; uses: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [tooSmallPerOrder.id],
  );
  assert.deepEqual(perOrderState.rows[0], { spent: "0", uses: "0" });

  const cumulative = {
    ...grant(userId, marketId, nowSec + 1_800),
    id: `grant:cumulative:${userId}`,
    maxTotalUsdcBaseUnits: 10_000_000,
  };
  await persistAgenticGrant(db, cumulative);
  const accepted = placeAction(marketId, "x:post:cap-total-1");
  await placeV2Order(db, {
    marketId,
    userId,
    assetSide: accepted.assetSide,
    action: accepted.action,
    limitPriceCents: accepted.limitPriceCents,
    sharesCenti: accepted.sharesCenti,
    tif: accepted.tif,
    expiresAtSec: accepted.expiresAtSec,
    idempotencyKey: accepted.idempotencyKey,
    agenticIntent: intentFor(cumulative, accepted, {
      nonce: "nonce:total:1",
      sourceEventId: accepted.idempotencyKey,
    }),
  });
  const rejected = placeAction(marketId, "x:post:cap-total-2");
  await expectCode("session_total_cap", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: rejected.assetSide,
    action: rejected.action,
    limitPriceCents: rejected.limitPriceCents,
    sharesCenti: rejected.sharesCenti,
    tif: rejected.tif,
    expiresAtSec: rejected.expiresAtSec,
    idempotencyKey: rejected.idempotencyKey,
    agenticIntent: intentFor(cumulative, rejected, {
      nonce: "nonce:total:2",
      sourceEventId: rejected.idempotencyKey,
    }),
  }));
  const cumulativeState = await db.query<{ spent: string; uses: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [cumulative.id],
  );
  assert.deepEqual(cumulativeState.rows[0], { spent: "5550000", uses: "1" });
});

test("expired grant rejects without creating an order or consumption", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-expired", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const expired = grant(userId, marketId, nowSec - 1);
  await persistAgenticGrant(db, expired);
  const action = placeAction(marketId, "x:post:expired");

  await expectCode("grant_expired", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: intentFor(expired, action),
  }));
  const state = await db.query<{ orders: string; uses: string }>(
    `SELECT
       (SELECT count(*)::text FROM v2_orders WHERE user_id=$2::uuid) AS orders,
       count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.id`,
    [expired.id, userId],
  );
  assert.deepEqual(state.rows[0], { orders: "0", uses: "0" });
});

test("nonce, source event and idempotency collisions fail closed", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-collision", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const grantValue = grant(userId, marketId, nowSec + 1_800);
  await persistAgenticGrant(db, grantValue);
  const firstAction = placeAction(marketId);
  const firstIntent = intentFor(grantValue, firstAction);
  await placeV2Order(db, {
    marketId,
    userId,
    assetSide: firstAction.assetSide,
    action: firstAction.action,
    limitPriceCents: firstAction.limitPriceCents,
    sharesCenti: firstAction.sharesCenti,
    tif: firstAction.tif,
    expiresAtSec: firstAction.expiresAtSec,
    idempotencyKey: firstAction.idempotencyKey,
    agenticIntent: firstIntent,
  });

  const changedAction = { ...firstAction, limitPriceCents: 54, idempotencyKey: "x:post:102" };
  const collision = intentFor(grantValue, changedAction, { sourceEventId: "x:post:102" });
  await expectCode("agentic_replay_collision", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: changedAction.assetSide,
    action: changedAction.action,
    limitPriceCents: changedAction.limitPriceCents,
    sharesCenti: changedAction.sharesCenti,
    tif: changedAction.tif,
    expiresAtSec: changedAction.expiresAtSec,
    idempotencyKey: changedAction.idempotencyKey,
    agenticIntent: collision,
  }));
});

test("a fresh grant cannot consume budget for an order created by another grant", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-origin", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const firstGrant = grant(userId, marketId, nowSec + 1_800);
  const secondGrant = {
    ...grant(userId, marketId, nowSec + 1_800),
    id: `grant:second:${userId}`,
    sessionDelegate: `delegate:second:${userId}`,
  };
  assert.equal(await persistAgenticGrant(db, firstGrant), "created");
  assert.equal(await persistAgenticGrant(db, firstGrant), "existing");
  await persistAgenticGrant(db, secondGrant);
  const action = placeAction(marketId);
  await placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: intentFor(firstGrant, action),
  });

  await expectCode("agentic_order_origin_mismatch", () => placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: intentFor(secondGrant, action, {
      nonce: "nonce:second",
      sourceEventId: "x:post:second",
    }),
  }));
  const secondState = await db.query<{ spent: string; uses: string }>(
    `SELECT g.spent_usdc::text AS spent,count(c.id)::text AS uses
       FROM v2_agentic_grants g
       LEFT JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE g.id=$1 GROUP BY g.spent_usdc`,
    [secondGrant.id],
  );
  assert.deepEqual(secondState.rows[0], { spent: "0", uses: "0" });
});

test("agentic cancellation is atomic and exact replay is harmless", async () => {
  const db = await makeTestDb();
  const nowSec = Math.floor(Date.now() / 1_000);
  const userId = await createUser(db, "agentic-cancel", "100");
  const marketId = await createMarket(db, nowSec + 3_600, userId);
  const grantValue = grant(userId, marketId, nowSec + 1_800);
  await persistAgenticGrant(db, grantValue);
  const action = placeAction(marketId);
  const placeIntent = intentFor(grantValue, action);
  const placed = await placeV2Order(db, {
    marketId,
    userId,
    assetSide: action.assetSide,
    action: action.action,
    limitPriceCents: action.limitPriceCents,
    sharesCenti: action.sharesCenti,
    tif: action.tif,
    expiresAtSec: action.expiresAtSec,
    idempotencyKey: action.idempotencyKey,
    agenticIntent: placeIntent,
  });
  const cancelAction = {
    capability: "order.cancel" as const,
    marketId,
    orderId: placed.orderId,
    idempotencyKey: "telegram:cancel:101",
  };
  const staleGrantSnapshot = { ...grantValue, spentUsdcBaseUnits: 0 };
  const cancelEnvelope = intentFor(staleGrantSnapshot, cancelAction, {
    channel: "telegram",
    externalIdentity: "telegram:user:77",
    sourceEventId: "telegram:update:101",
    nonce: "nonce:2",
  });
  const cancelIntent = await authorizeAgenticCancelOrder(
    provider(cancelEnvelope),
    {},
    cancelAction,
    {
      ...authOptions(staleGrantSnapshot, nowSec),
      channel: "telegram" as const,
      externalIdentity: "telegram:user:77",
    },
  );
  await cancelV2Order(db, placed.orderId, userId, cancelIntent);
  await cancelV2Order(db, placed.orderId, userId, cancelIntent);

  const state = await db.query<{ status: string; uses: string; spent: string }>(
    `SELECT o.status,count(c.id)::text AS uses,max(g.spent_usdc)::text AS spent
       FROM v2_orders o
       JOIN v2_agentic_grants g ON g.user_id=o.user_id
       JOIN v2_agentic_consumptions c ON c.grant_id=g.id
      WHERE o.id=$1 GROUP BY o.status`,
    [placed.orderId],
  );
  assert.deepEqual(state.rows[0], { status: "cancelled", uses: "2", spent: "5550000" });
});
