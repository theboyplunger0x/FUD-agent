import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import {
  AgenticAuthorizationError,
  type AgenticV2Action,
} from "./agenticAuthorization.js";
import {
  executeAgenticV2Action,
  isAgenticV2ExecutionEnabled,
  type AgenticExecutionDependencies,
} from "./agenticExecution.js";
import {
  SolanaSessionAuthorizationProvider,
  solanaAgenticActionBytes,
  solanaAgenticGrantBytes,
  type SolanaAgenticActionPayloadV1,
  type SolanaAgenticEnvelopeV1,
  type SolanaAgenticGrantDefinitionV1,
} from "./solanaAgenticProvider.js";
import { createMarket, createUser, makeTestDb } from "./testdb.js";

const NOW = 1_800_000_000;
const X_ID = "123456789";
const TELEGRAM_ID = "987654321";

function envelopeFor(input: {
  grant: SolanaAgenticGrantDefinitionV1;
  action: AgenticV2Action;
  channel: "x" | "telegram";
  externalIdentity: string;
  sourceEventId: string;
  nonce: string;
  wallet: Keypair;
  delegate: Keypair;
}): SolanaAgenticEnvelopeV1 {
  const intent: SolanaAgenticActionPayloadV1 = {
    version: 1,
    grantId: input.grant.id,
    userId: input.grant.userId,
    wallet: input.grant.wallet,
    channel: input.channel,
    externalIdentity: input.externalIdentity,
    sourceEventId: input.sourceEventId,
    nonce: input.nonce,
    action: input.action,
  };
  return {
    version: 1,
    grant: input.grant,
    grantSignature: Buffer.from(
      nacl.sign.detached(solanaAgenticGrantBytes(input.grant), input.wallet.secretKey),
    ).toString("base64"),
    intent,
    intentSignature: Buffer.from(
      nacl.sign.detached(solanaAgenticActionBytes(intent), input.delegate.secretKey),
    ).toString("base64"),
  };
}

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

test("kill switch is exact and blocks before identity/provider work", async () => {
  assert.equal(isAgenticV2ExecutionEnabled({ FUDV2_AGENTIC_ENABLED: "true" }), true);
  assert.equal(isAgenticV2ExecutionEnabled({ FUDV2_AGENTIC_ENABLED: "TRUE" }), false);
  assert.equal(isAgenticV2ExecutionEnabled({}), false);
  let touched = false;
  await expectCode("agentic_execution_disabled", () => executeAgenticV2Action(
    {} as never,
    {
      identity: { channel: "x", externalId: X_ID },
      envelope: {},
      action: {
        capability: "order.cancel",
        marketId: "market",
        orderId: "order",
        idempotencyKey: "x:cancel:1",
      },
    },
    {
      enabled: false,
      provider: { verify: async () => { touched = true; throw new Error("unexpected"); } },
      resolveWalletBinding: async () => { touched = true; throw new Error("unexpected"); },
      targetProgram: Keypair.generate().publicKey.toBase58(),
      environment: "beta",
      audience: "fud-v2-order-engine",
    },
  ));
  assert.equal(touched, false);
});

test("X place and Telegram cancel use one signed grant through the real V2 engine", async () => {
  const db = await makeTestDb();
  const userId = await createUser(db, "agentic-user", "100.000000");
  const marketId = await createMarket(db, NOW + 7_200, userId);
  await db.query(
    `UPDATE users SET x_user_id=$1,telegram_id=$2::bigint WHERE id=$3::uuid`,
    [X_ID, TELEGRAM_ID, userId],
  );
  const wallet = Keypair.generate();
  const delegate = Keypair.generate();
  const targetProgram = Keypair.generate().publicKey.toBase58();
  const grant: SolanaAgenticGrantDefinitionV1 = {
    version: 1,
    id: "grant-e2e-1",
    provider: "magic",
    userId,
    wallet: wallet.publicKey.toBase58(),
    chain: "solana",
    sessionDelegate: delegate.publicKey.toBase58(),
    targetProgram,
    environment: "beta",
    audience: "fud-v2-order-engine",
    allowedChannels: ["x", "telegram"],
    allowedCapabilities: ["order.place", "order.cancel"],
    allowedMarketIds: [marketId],
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 20_000_000,
    expiresAtSec: NOW + 3_600,
  };
  const dependencies: AgenticExecutionDependencies = {
    enabled: true,
    provider: new SolanaSessionAuthorizationProvider(),
    resolveWalletBinding: async (_db, resolvedUserId) => {
      assert.equal(resolvedUserId, userId);
      return { wallet: wallet.publicKey.toBase58(), provider: "magic" };
    },
    targetProgram,
    environment: "beta",
    audience: "fud-v2-order-engine",
    nowSec: NOW,
  };
  const placeAction: AgenticV2Action = {
    capability: "order.place",
    marketId,
    assetSide: "long",
    action: "buy",
    limitPriceCents: 55,
    sharesCenti: 1_000,
    tif: "gtc",
    expiresAtSec: null,
    idempotencyKey: "x:tweet:place-1",
  };
  const placeEnvelope = envelopeFor({
    grant,
    action: placeAction,
    channel: "x",
    externalIdentity: `x:${X_ID}`,
    sourceEventId: "x:tweet:place-1",
    nonce: "1",
    wallet,
    delegate,
  });
  const placed = await executeAgenticV2Action(db, {
    identity: { channel: "x", externalId: X_ID, username: "mutable-handle" },
    envelope: placeEnvelope,
    action: placeAction,
  }, dependencies);
  assert.equal(placed.capability, "order.place");
  if (placed.capability !== "order.place") throw new Error("bad result");
  assert.equal(placed.result.status, "open");

  const replay = await executeAgenticV2Action(db, {
    identity: { channel: "x", externalId: X_ID, username: "renamed-handle" },
    envelope: placeEnvelope,
    action: placeAction,
  }, dependencies);
  assert.equal(replay.capability, "order.place");
  if (replay.capability !== "order.place") throw new Error("bad replay result");
  assert.equal(replay.result.orderId, placed.result.orderId);
  assert.equal(replay.result.idempotentReplay, true);

  const cancelAction: AgenticV2Action = {
    capability: "order.cancel",
    marketId,
    orderId: placed.result.orderId,
    idempotencyKey: "telegram:message:cancel-1",
  };
  const cancelEnvelope = envelopeFor({
    grant,
    action: cancelAction,
    channel: "telegram",
    externalIdentity: `telegram:${TELEGRAM_ID}`,
    sourceEventId: "telegram:message:cancel-1",
    nonce: "2",
    wallet,
    delegate,
  });
  await expectCode("telegram_dm_required", () => executeAgenticV2Action(db, {
    identity: { channel: "telegram", externalId: TELEGRAM_ID },
    privateChat: false,
    envelope: cancelEnvelope,
    action: cancelAction,
  }, dependencies));
  const cancelled = await executeAgenticV2Action(db, {
    identity: { channel: "telegram", externalId: TELEGRAM_ID },
    privateChat: true,
    envelope: cancelEnvelope,
    action: cancelAction,
  }, dependencies);
  assert.deepEqual(cancelled, { capability: "order.cancel", result: { cancelled: true } });
  const row = await db.query<{ status: string }>(`SELECT status FROM v2_orders WHERE id=$1`, [
    placed.result.orderId,
  ]);
  assert.equal(row.rows[0].status, "cancelled");
  const consumptionCount = await db.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM v2_agentic_consumptions WHERE grant_id=$1`,
    [grant.id],
  );
  assert.equal(consumptionCount.rows[0].count, 2);
});

test("channel policy and expected Magic wallet binding fail closed", async () => {
  const db = await makeTestDb();
  const userId = await createUser(db, "bound-user", "100.000000");
  const marketId = await createMarket(db, NOW + 7_200, userId);
  await db.query(`UPDATE users SET x_user_id=$1 WHERE id=$2::uuid`, [X_ID, userId]);
  const wallet = Keypair.generate();
  const delegate = Keypair.generate();
  const targetProgram = Keypair.generate().publicKey.toBase58();
  const grant: SolanaAgenticGrantDefinitionV1 = {
    version: 1,
    id: "grant-binding-1",
    provider: "magic",
    userId,
    wallet: wallet.publicKey.toBase58(),
    chain: "solana",
    sessionDelegate: delegate.publicKey.toBase58(),
    targetProgram,
    environment: "beta",
    audience: "fud-v2-order-engine",
    allowedChannels: ["x"],
    allowedCapabilities: ["order.cancel"],
    allowedMarketIds: [marketId],
    maxPerOrderUsdcBaseUnits: 1,
    maxTotalUsdcBaseUnits: 1,
    expiresAtSec: NOW + 3_600,
  };
  const action: AgenticV2Action = {
    capability: "order.cancel",
    marketId,
    orderId: "33333333-3333-4333-8333-333333333333",
    idempotencyKey: "x:cancel:forbidden",
  };
  const envelope = envelopeFor({
    grant,
    action,
    channel: "x",
    externalIdentity: `x:${X_ID}`,
    sourceEventId: "x:cancel:forbidden",
    nonce: "1",
    wallet,
    delegate,
  });
  const baseDependencies: AgenticExecutionDependencies = {
    enabled: true,
    provider: new SolanaSessionAuthorizationProvider(),
    resolveWalletBinding: async () => ({ wallet: wallet.publicKey.toBase58(), provider: "magic" }),
    targetProgram,
    environment: "beta",
    audience: "fud-v2-order-engine",
    nowSec: NOW,
  };
  await expectCode("x_action_not_supported", () => executeAgenticV2Action(db, {
    identity: { channel: "x", externalId: X_ID },
    envelope,
    action,
  }, baseDependencies));

  const placeAction: AgenticV2Action = {
    capability: "order.place",
    marketId,
    assetSide: "long",
    action: "buy",
    limitPriceCents: 50,
    sharesCenti: 1_000,
    tif: "gtc",
    expiresAtSec: null,
    idempotencyKey: "x:place:wallet-mismatch",
  };
  const placeGrant = {
    ...grant,
    id: "grant-binding-2",
    allowedCapabilities: ["order.place"] as const,
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 10_000_000,
  };
  const placeEnvelope = envelopeFor({
    grant: placeGrant,
    action: placeAction,
    channel: "x",
    externalIdentity: `x:${X_ID}`,
    sourceEventId: "x:place:wallet-mismatch",
    nonce: "2",
    wallet,
    delegate,
  });
  await expectCode("wallet_mismatch", () => executeAgenticV2Action(db, {
    identity: { channel: "x", externalId: X_ID },
    envelope: placeEnvelope,
    action: placeAction,
  }, {
    ...baseDependencies,
    resolveWalletBinding: async () => ({
      wallet: Keypair.generate().publicKey.toBase58(),
      provider: "magic",
    }),
  }));
});
