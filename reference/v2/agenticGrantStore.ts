import { createHash } from "node:crypto";
import type { Queryable } from "./dbClient.js";
import {
  AgenticAuthorizationError,
  agenticOrderAuthorizationValueUsdcBaseUnits,
  type AgenticCapability,
  type AgenticChannel,
  type AgenticGrant,
  type AgenticV2Action,
  type VerifiedAgenticIntent,
} from "./agenticAuthorization.js";
import type { SolanaAgenticGrantDefinitionV1 } from "./solanaAgenticProvider.js";

type GrantRow = {
  id: string;
  version: number;
  provider: string;
  user_id: string;
  wallet_address: string;
  chain: "solana";
  session_delegate: string;
  target_program: string;
  environment: string;
  audience: string;
  allowed_channels: unknown;
  allowed_capabilities: unknown;
  allowed_market_ids: unknown | null;
  max_per_order_usdc: string;
  max_total_usdc: string;
  spent_usdc: string;
  expires_at_sec: string;
  revoked_at_sec: string | null;
  database_now_sec: string;
  definition_hash: string;
};

type ConsumptionRow = {
  id: string;
  user_id: string;
  channel: AgenticChannel;
  capability: AgenticCapability;
  external_identity: string;
  source_event_id: string;
  nonce: string;
  idempotency_key: string;
  action_fingerprint: string;
  authorized_usdc: string;
  order_id: string | null;
};

export type AgenticConsumption = {
  id: string;
  replay: boolean;
  orderId: string | null;
  authorizationValueUsdcBaseUnits: number;
};

export type ActiveAgenticGrantMaterial = {
  grant: SolanaAgenticGrantDefinitionV1;
  grantSignature: string;
};

function safeInteger(value: string, code: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new AgenticAuthorizationError(code);
  return parsed;
}

function stringArray(value: unknown, code: string): string[] {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!Array.isArray(parsed)
      || parsed.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new AgenticAuthorizationError(code);
  }
  return parsed;
}

function sorted(values: readonly string[]): string[] {
  return [...values].sort();
}

function grantDefinition(grant: AgenticGrant): Record<string, unknown> {
  return {
    version: grant.version,
    id: grant.id,
    provider: grant.provider,
    userId: grant.userId,
    wallet: grant.wallet,
    chain: grant.chain,
    sessionDelegate: grant.sessionDelegate,
    targetProgram: grant.targetProgram,
    environment: grant.environment,
    audience: grant.audience,
    allowedChannels: sorted(grant.allowedChannels),
    allowedCapabilities: sorted(grant.allowedCapabilities),
    allowedMarketIds: grant.allowedMarketIds === null ? null : sorted(grant.allowedMarketIds),
    maxPerOrderUsdcBaseUnits: grant.maxPerOrderUsdcBaseUnits,
    maxTotalUsdcBaseUnits: grant.maxTotalUsdcBaseUnits,
    expiresAtSec: grant.expiresAtSec,
  };
}

export function agenticGrantDefinitionHash(grant: AgenticGrant): string {
  return createHash("sha256").update(JSON.stringify(grantDefinition(grant))).digest("hex");
}

export function agenticActionFingerprint(action: AgenticV2Action): string {
  const canonical = action.capability === "order.place"
    ? {
        capability: action.capability,
        marketId: action.marketId,
        assetSide: action.assetSide,
        action: action.action,
        limitPriceCents: action.limitPriceCents,
        sharesCenti: action.sharesCenti,
        tif: action.tif,
        expiresAtSec: action.expiresAtSec,
        idempotencyKey: action.idempotencyKey,
      }
    : {
        capability: action.capability,
        marketId: action.marketId,
        orderId: action.orderId,
        idempotencyKey: action.idempotencyKey,
      };
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

function grantFromRow(row: GrantRow): AgenticGrant {
  const allowedMarketIds = row.allowed_market_ids === null
    ? null
    : stringArray(row.allowed_market_ids, "bad_persisted_market_scope");
  return {
    version: row.version as 1,
    id: row.id,
    provider: row.provider,
    userId: row.user_id,
    wallet: row.wallet_address,
    chain: row.chain,
    sessionDelegate: row.session_delegate,
    targetProgram: row.target_program,
    environment: row.environment,
    audience: row.audience,
    allowedChannels: stringArray(row.allowed_channels, "bad_persisted_channels") as AgenticChannel[],
    allowedCapabilities: stringArray(
      row.allowed_capabilities,
      "bad_persisted_capabilities",
    ) as AgenticCapability[],
    allowedMarketIds,
    maxPerOrderUsdcBaseUnits: safeInteger(row.max_per_order_usdc, "bad_persisted_limit"),
    maxTotalUsdcBaseUnits: safeInteger(row.max_total_usdc, "bad_persisted_limit"),
    spentUsdcBaseUnits: safeInteger(row.spent_usdc, "bad_persisted_spend"),
    expiresAtSec: safeInteger(row.expires_at_sec, "bad_persisted_expiry"),
    revokedAtSec: row.revoked_at_sec === null
      ? null
      : safeInteger(row.revoked_at_sec, "bad_persisted_revocation"),
  };
}

/**
 * Load the one active, browser-authorized grant used by the social gateway.
 * The database clock is authoritative. Grants created before the signature
 * column landed deliberately fail closed and must be renewed by the user.
 */
export async function loadActiveAgenticGrantMaterial(
  db: Queryable,
  userId: string,
  provider = "magic",
): Promise<ActiveAgenticGrantMaterial> {
  const selected = await db.query<GrantRow & { wallet_grant_signature: string | null }>(
    `SELECT id,version,provider,user_id,wallet_address,chain,session_delegate,target_program,
            environment,audience,allowed_channels,allowed_capabilities,allowed_market_ids,
            max_per_order_usdc::text,max_total_usdc::text,spent_usdc::text,
            floor(extract(epoch from expires_at))::bigint::text AS expires_at_sec,
            CASE WHEN revoked_at IS NULL THEN NULL
                 ELSE floor(extract(epoch from revoked_at))::bigint::text END AS revoked_at_sec,
            floor(extract(epoch from clock_timestamp()))::bigint::text AS database_now_sec,
            definition_hash,wallet_grant_signature
       FROM v2_agentic_grants
      WHERE user_id=$1::uuid AND provider=$2 AND revoked_at IS NULL
        AND expires_at>clock_timestamp()
      ORDER BY created_at DESC
      LIMIT 1`,
    [userId, provider],
  );
  const row = selected.rows[0];
  if (!row) throw new AgenticAuthorizationError("active_grant_not_found");
  if (!row.wallet_grant_signature?.trim()) {
    throw new AgenticAuthorizationError("grant_signature_not_stored");
  }
  const persisted = grantFromRow(row);
  if (persisted.revokedAtSec !== null) throw new AgenticAuthorizationError("grant_revoked");
  if (agenticGrantDefinitionHash(persisted) !== row.definition_hash) {
    throw new AgenticAuthorizationError("grant_definition_mismatch");
  }
  const { spentUsdcBaseUnits: _spent, revokedAtSec: _revoked, ...grant } = persisted;
  return { grant, grantSignature: row.wallet_grant_signature };
}

function validatePersistableGrant(grant: AgenticGrant): void {
  const required = [
    grant.id,
    grant.provider,
    grant.userId,
    grant.wallet,
    grant.sessionDelegate,
    grant.targetProgram,
    grant.environment,
    grant.audience,
  ];
  if (required.some((value) => typeof value !== "string" || value.trim().length === 0)) {
    throw new AgenticAuthorizationError("bad_grant_definition");
  }
  if (grant.version !== 1 || grant.chain !== "solana") {
    throw new AgenticAuthorizationError("bad_grant_definition");
  }
  for (const value of [
    grant.maxPerOrderUsdcBaseUnits,
    grant.maxTotalUsdcBaseUnits,
    grant.spentUsdcBaseUnits,
    grant.expiresAtSec,
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new AgenticAuthorizationError("bad_grant_definition");
    }
  }
  if (grant.expiresAtSec === 0
      || grant.spentUsdcBaseUnits > grant.maxTotalUsdcBaseUnits
      || (grant.revokedAtSec !== null
        && (!Number.isSafeInteger(grant.revokedAtSec) || grant.revokedAtSec < 0))) {
    throw new AgenticAuthorizationError("bad_grant_definition");
  }
  stringArray(grant.allowedChannels, "bad_grant_definition");
  stringArray(grant.allowedCapabilities, "bad_grant_definition");
  if (grant.allowedMarketIds !== null) stringArray(grant.allowedMarketIds, "bad_grant_definition");
}

/**
 * Grants are immutable definitions. Revocation and cumulative consumption are
 * mutable server-side state. Reusing an id with wider/different scope fails.
 */
export async function persistAgenticGrant(
  db: Queryable,
  grant: AgenticGrant,
): Promise<"created" | "existing"> {
  validatePersistableGrant(grant);
  const definitionHash = agenticGrantDefinitionHash(grant);
  const inserted = await db.query<{ id: string }>(
    `INSERT INTO v2_agentic_grants
      (id,version,provider,user_id,wallet_address,chain,session_delegate,target_program,
       environment,audience,allowed_channels,allowed_capabilities,allowed_market_ids,
       max_per_order_usdc,max_total_usdc,spent_usdc,expires_at,revoked_at,definition_hash)
     VALUES
      ($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,
       $14::bigint,$15::bigint,$16::bigint,to_timestamp($17::double precision),
       CASE WHEN $18::bigint IS NULL THEN NULL ELSE to_timestamp($18::double precision) END,$19)
     ON CONFLICT (id) DO NOTHING
     RETURNING id`,
    [
      grant.id,
      grant.version,
      grant.provider,
      grant.userId,
      grant.wallet,
      grant.chain,
      grant.sessionDelegate,
      grant.targetProgram,
      grant.environment,
      grant.audience,
      JSON.stringify(grant.allowedChannels),
      JSON.stringify(grant.allowedCapabilities),
      grant.allowedMarketIds === null ? null : JSON.stringify(grant.allowedMarketIds),
      grant.maxPerOrderUsdcBaseUnits,
      grant.maxTotalUsdcBaseUnits,
      grant.spentUsdcBaseUnits,
      grant.expiresAtSec,
      grant.revokedAtSec,
      definitionHash,
    ],
  );
  const selected = await db.query<{ definition_hash: string }>(
    `SELECT definition_hash FROM v2_agentic_grants WHERE id=$1`,
    [grant.id],
  );
  if (!selected.rows[0] || selected.rows[0].definition_hash !== definitionHash) {
    throw new AgenticAuthorizationError("grant_id_reused_with_different_scope");
  }
  return inserted.rows[0] ? "created" : "existing";
}

/** Must run inside a transaction that owns the canonical user-row lock. */
export async function activateExclusiveAgenticGrantInTransaction(
  db: Queryable,
  grant: AgenticGrant,
): Promise<void> {
  await db.query(`SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, [grant.userId]);
  await persistAgenticGrant(db, grant);
  const stored = await db.query<{ revoked_at: string | Date | null }>(
    `SELECT revoked_at FROM v2_agentic_grants WHERE id=$1 AND user_id=$2::uuid`,
    [grant.id, grant.userId],
  );
  if (!stored.rows[0] || stored.rows[0].revoked_at !== null) {
    throw new AgenticAuthorizationError("grant_revoked");
  }
  await db.query(
    `UPDATE v2_agentic_grants
        SET revoked_at=COALESCE(revoked_at,clock_timestamp()),updated_at=clock_timestamp()
      WHERE user_id=$1::uuid AND provider=$2 AND id<>$3 AND revoked_at IS NULL`,
    [grant.userId, grant.provider, grant.id],
  );
}

/**
 * Must run inside a transaction. Sharing the canonical user-row lock with
 * activation makes consent/revoke linearizable instead of allowing a revoke
 * UPDATE to miss a concurrently-created grant.
 */
export async function revokeAllAgenticGrantsForUserInTransaction(
  db: Queryable,
  userId: string,
  provider: string,
): Promise<void> {
  if (!userId.trim() || !provider.trim()) {
    throw new AgenticAuthorizationError("bad_grant_revocation");
  }
  await db.query(`SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, [userId]);
  await db.query(
    `UPDATE v2_agentic_grants
        SET revoked_at=COALESCE(revoked_at,clock_timestamp()),updated_at=clock_timestamp()
      WHERE user_id=$1::uuid AND provider=$2 AND revoked_at IS NULL`,
    [userId, provider],
  );
}

export async function revokeAgenticGrant(
  db: Queryable,
  grantId: string,
  revokedAtSec: number,
): Promise<void> {
  if (!Number.isSafeInteger(revokedAtSec) || revokedAtSec < 0) {
    throw new AgenticAuthorizationError("bad_grant_revocation");
  }
  const result = await db.query(
    `UPDATE v2_agentic_grants
        SET revoked_at=COALESCE(revoked_at,to_timestamp($2::double precision)),updated_at=clock_timestamp()
      WHERE id=$1 RETURNING id`,
    [grantId, revokedAtSec],
  );
  if (!result.rows[0]) throw new AgenticAuthorizationError("grant_not_found");
}

function exactReplay(row: ConsumptionRow, intent: VerifiedAgenticIntent, fingerprint: string): boolean {
  return row.user_id === intent.userId
    && row.channel === intent.channel
    && row.capability === intent.action.capability
    && row.external_identity === intent.externalIdentity
    && row.source_event_id === intent.sourceEventId
    && row.nonce === intent.nonce
    && row.idempotency_key === intent.action.idempotencyKey
    && row.action_fingerprint === fingerprint;
}

/** Must run inside the same transaction as the order mutation. */
export async function consumeAgenticIntentInTransaction(
  db: Queryable,
  intent: VerifiedAgenticIntent,
): Promise<AgenticConsumption> {
  const selected = await db.query<GrantRow>(
    `SELECT id,version,provider,user_id,wallet_address,chain,session_delegate,target_program,
            environment,audience,allowed_channels,allowed_capabilities,allowed_market_ids,
            max_per_order_usdc::text,max_total_usdc::text,spent_usdc::text,
            floor(extract(epoch from expires_at))::bigint::text AS expires_at_sec,
            CASE WHEN revoked_at IS NULL THEN NULL
                 ELSE floor(extract(epoch from revoked_at))::bigint::text END AS revoked_at_sec,
            floor(extract(epoch from clock_timestamp()))::bigint::text AS database_now_sec,
            definition_hash
       FROM v2_agentic_grants WHERE id=$1 FOR UPDATE`,
    [intent.grant.id],
  );
  if (!selected.rows[0]) throw new AgenticAuthorizationError("grant_not_found");
  const row = selected.rows[0];
  const persisted = grantFromRow(row);
  const databaseNowSec = safeInteger(row.database_now_sec, "bad_database_time");
  const persistedHash = agenticGrantDefinitionHash(persisted);
  if (row.definition_hash !== persistedHash
      || agenticGrantDefinitionHash(intent.grant) !== persistedHash) {
    throw new AgenticAuthorizationError("grant_definition_mismatch");
  }
  if (persisted.userId !== intent.userId) throw new AgenticAuthorizationError("user_mismatch");
  if (persisted.wallet !== intent.wallet) throw new AgenticAuthorizationError("wallet_mismatch");
  if (persisted.revokedAtSec !== null) throw new AgenticAuthorizationError("grant_revoked");
  if (persisted.expiresAtSec <= databaseNowSec) throw new AgenticAuthorizationError("grant_expired");
  if (!persisted.allowedChannels.includes(intent.channel)) {
    throw new AgenticAuthorizationError("channel_not_allowed");
  }
  if (!persisted.allowedCapabilities.includes(intent.action.capability)) {
    throw new AgenticAuthorizationError("capability_not_allowed");
  }
  if (persisted.allowedMarketIds !== null
      && !persisted.allowedMarketIds.includes(intent.action.marketId)) {
    throw new AgenticAuthorizationError("market_not_allowed");
  }

  const fingerprint = agenticActionFingerprint(intent.action);
  const collisions = await db.query<ConsumptionRow>(
    `SELECT id,user_id,channel,capability,external_identity,source_event_id,nonce,
            idempotency_key,action_fingerprint,authorized_usdc::text,order_id
       FROM v2_agentic_consumptions
      WHERE grant_id=$1
        AND (nonce=$2 OR source_event_id=$3 OR idempotency_key=$4)
      FOR UPDATE`,
    [intent.grant.id, intent.nonce, intent.sourceEventId, intent.action.idempotencyKey],
  );
  if (collisions.rows.length > 0) {
    if (collisions.rows.length !== 1 || !exactReplay(collisions.rows[0], intent, fingerprint)) {
      throw new AgenticAuthorizationError("agentic_replay_collision");
    }
    if (!collisions.rows[0].order_id) {
      throw new AgenticAuthorizationError("incomplete_agentic_consumption");
    }
    return {
      id: collisions.rows[0].id,
      replay: true,
      orderId: collisions.rows[0].order_id,
      authorizationValueUsdcBaseUnits: safeInteger(
        collisions.rows[0].authorized_usdc,
        "bad_persisted_spend",
      ),
    };
  }

  const authorizationValue = intent.action.capability === "order.place"
    ? agenticOrderAuthorizationValueUsdcBaseUnits(intent.action)
    : 0;
  if (authorizationValue > persisted.maxPerOrderUsdcBaseUnits) {
    throw new AgenticAuthorizationError("per_order_cap");
  }
  const nextSpend = persisted.spentUsdcBaseUnits + authorizationValue;
  if (!Number.isSafeInteger(nextSpend)) throw new AgenticAuthorizationError("unsafe_session_spend");
  if (nextSpend > persisted.maxTotalUsdcBaseUnits) {
    throw new AgenticAuthorizationError("session_total_cap");
  }

  const inserted = await db.query<{ id: string }>(
    `INSERT INTO v2_agentic_consumptions
      (grant_id,user_id,channel,capability,external_identity,source_event_id,nonce,
       idempotency_key,action_fingerprint,authorized_usdc)
     VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10::bigint)
     RETURNING id`,
    [
      intent.grant.id,
      intent.userId,
      intent.channel,
      intent.action.capability,
      intent.externalIdentity,
      intent.sourceEventId,
      intent.nonce,
      intent.action.idempotencyKey,
      fingerprint,
      authorizationValue,
    ],
  );
  const updated = await db.query(
    `UPDATE v2_agentic_grants
        SET spent_usdc=spent_usdc+$2::bigint,updated_at=clock_timestamp()
      WHERE id=$1 AND spent_usdc+$2::bigint<=max_total_usdc
      RETURNING id`,
    [intent.grant.id, authorizationValue],
  );
  if (!updated.rows[0]) throw new AgenticAuthorizationError("session_total_cap");
  return {
    id: inserted.rows[0].id,
    replay: false,
    orderId: null,
    authorizationValueUsdcBaseUnits: authorizationValue,
  };
}

/** Must run before commit; a committed consumption always has a durable receipt. */
export async function bindAgenticConsumptionToOrder(
  db: Queryable,
  consumptionId: string,
  orderId: string,
): Promise<void> {
  const updated = await db.query(
    `UPDATE v2_agentic_consumptions
        SET order_id=$2::uuid
      WHERE id=$1::uuid AND (order_id IS NULL OR order_id=$2::uuid)
      RETURNING id`,
    [consumptionId, orderId],
  );
  if (!updated.rows[0]) throw new AgenticAuthorizationError("agentic_receipt_mismatch");
}
