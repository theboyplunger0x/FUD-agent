import type { Queryable } from "./dbClient.js";
import {
  AgenticAuthorizationError,
  authorizeAgenticCancelOrder,
  authorizeAgenticPlaceOrder,
  type AgenticAuthorizationProvider,
  type AgenticV2Action,
} from "./agenticAuthorization.js";
import {
  resolveAgenticIdentity,
  type AgenticExternalIdentity,
} from "./agenticIdentity.js";
import { persistAgenticGrant } from "./agenticGrantStore.js";
import {
  cancelV2Order,
  placeV2Order,
  type PlaceOrderResult,
} from "./executor.js";

export type AgenticWalletBinding = {
  wallet: string;
  provider: string;
};

export type ResolveAgenticWalletBinding = (
  db: Queryable,
  userId: string,
) => Promise<AgenticWalletBinding>;

export type ExecuteAgenticV2Input = {
  identity: AgenticExternalIdentity;
  /** Telegram value-moving actions must originate in a private chat. */
  privateChat?: boolean;
  envelope: unknown;
  action: AgenticV2Action;
};

export type AgenticExecutionDependencies = {
  provider: AgenticAuthorizationProvider;
  resolveWalletBinding: ResolveAgenticWalletBinding;
  targetProgram: string;
  environment: string;
  audience: string;
  treasuryUserId?: string | null;
  nowSec?: number;
  /** Tests may override this; production defaults to the exact env kill switch. */
  enabled?: boolean;
};

export type AgenticV2ExecutionResult =
  | { capability: "order.place"; result: PlaceOrderResult }
  | { capability: "order.cancel"; result: { cancelled: true } };

export function isAgenticV2ExecutionEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return env.FUDV2_AGENTIC_ENABLED === "true";
}

function assertChannelPolicy(input: ExecuteAgenticV2Input): void {
  if (input.identity.channel === "x" && input.action.capability !== "order.place") {
    throw new AgenticAuthorizationError("x_action_not_supported");
  }
  if (input.identity.channel === "telegram" && input.privateChat !== true) {
    throw new AgenticAuthorizationError("telegram_dm_required");
  }
}

/**
 * The single social-to-engine seam. It resolves immutable identity, verifies
 * the wallet and delegate signatures, persists the immutable grant, then calls
 * the normal V2 executor. It deliberately contains no matching or money math.
 */
export async function executeAgenticV2Action(
  db: Queryable,
  input: ExecuteAgenticV2Input,
  dependencies: AgenticExecutionDependencies,
): Promise<AgenticV2ExecutionResult> {
  if ((dependencies.enabled ?? isAgenticV2ExecutionEnabled()) !== true) {
    throw new AgenticAuthorizationError("agentic_execution_disabled");
  }
  assertChannelPolicy(input);
  const identity = await resolveAgenticIdentity(db, input.identity);
  const binding = await dependencies.resolveWalletBinding(db, identity.userId);
  const options = {
    userId: identity.userId,
    channel: identity.channel,
    externalIdentity: identity.externalIdentity,
    wallet: binding.wallet,
    provider: binding.provider,
    chain: "solana" as const,
    targetProgram: dependencies.targetProgram,
    environment: dependencies.environment,
    audience: dependencies.audience,
    nowSec: dependencies.nowSec ?? Math.floor(Date.now() / 1000),
  };

  if (input.action.capability === "order.place") {
    const verified = await authorizeAgenticPlaceOrder(
      dependencies.provider,
      input.envelope,
      input.action,
      options,
    );
    await persistAgenticGrant(db, verified.grant);
    const result = await placeV2Order(db, {
      marketId: input.action.marketId,
      userId: identity.userId,
      assetSide: input.action.assetSide,
      action: input.action.action,
      limitPriceCents: input.action.limitPriceCents,
      sharesCenti: input.action.sharesCenti,
      tif: input.action.tif,
      expiresAtSec: input.action.expiresAtSec,
      idempotencyKey: input.action.idempotencyKey,
      treasuryUserId: dependencies.treasuryUserId,
      source: "limit",
      metadata: {
        agenticChannel: identity.channel,
        agenticSourceEventId: verified.sourceEventId,
        agenticGrantId: verified.grant.id,
      },
      agenticIntent: verified,
    });
    return { capability: "order.place", result };
  }

  const verified = await authorizeAgenticCancelOrder(
    dependencies.provider,
    input.envelope,
    input.action,
    options,
  );
  await persistAgenticGrant(db, verified.grant);
  await cancelV2Order(db, input.action.orderId, identity.userId, verified);
  return { capability: "order.cancel", result: { cancelled: true } };
}
