import type { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import { LAZY_ENV } from "../services/lazyMarketService.js";
import { AgenticAuthorizationError } from "../v2/agenticAuthorization.js";
import { AwsKmsAgenticDelegateSigner } from "../v2/agenticDelegateSigner.js";
import {
  agenticConsentPolicy,
  assertAgenticGrantMatchesConsent,
  prepareAgenticGrant,
} from "../v2/agenticGrantConsent.js";
import {
  activateExclusiveAgenticGrantInTransaction,
  revokeAllAgenticGrantsForUserInTransaction,
} from "../v2/agenticGrantStore.js";
import { resolveMagicSolanaWalletBinding } from "../v2/magicAgenticBinding.js";
import {
  solanaAgenticGrantBytes,
  verifySolanaAgenticGrantSignature,
} from "../v2/solanaAgenticProvider.js";

function runtimeStatus(): { ready: boolean; reason?: string } {
  if (process.env.FUDV2_AGENTIC_ENABLED !== "true") {
    return { ready: false, reason: "agentic execution is disabled" };
  }
  if (!process.env.AGENTIC_DELEGATE_SOL_KMS_KEY_ID?.trim()) {
    return { ready: false, reason: "agentic delegate is not configured" };
  }
  if (!(process.env.AWS_REGION?.trim() || process.env.KMS_AWS_REGION?.trim())) {
    return { ready: false, reason: "agentic delegate region is not configured" };
  }
  try {
    agenticConsentPolicy(process.env, LAZY_ENV);
    return { ready: true };
  } catch (error) {
    return { ready: false, reason: error instanceof Error ? error.message : "invalid agentic policy" };
  }
}

function publicStatus(row: {
  id: string;
  created_at: string | Date;
  expires_at: string | Date;
  revoked_at: string | Date | null;
  max_per_order_usdc: string;
  max_total_usdc: string;
} | undefined, walletReady: boolean) {
  const runtime = runtimeStatus();
  const active = !!row && row.revoked_at === null && new Date(row.expires_at).getTime() > Date.now();
  return {
    active,
    runtime_ready: runtime.ready,
    wallet_ready: walletReady,
    reason: runtime.reason,
    grant_id: row?.id,
    created_at: row?.created_at,
    expires_at: row?.expires_at,
    revoked_at: row?.revoked_at,
    per_order_usdc: row ? Number(row.max_per_order_usdc) / 1_000_000 : undefined,
    total_usdc: row ? Number(row.max_total_usdc) / 1_000_000 : undefined,
  };
}

export async function registerV2AgenticConsentRoutes(app: FastifyInstance): Promise<void> {
  const authenticate = { preHandler: [(app as any).authenticate] };

  app.get("/v2/agentic/grant", authenticate, async (req: any) => {
    const userId = req.user.userId as string;
    const user = await db.query<{ wallet: string | null; magic_issuer: string | null }>(
      `SELECT solana_wallet_address AS wallet,magic_issuer FROM users WHERE id=$1::uuid`,
      [userId],
    );
    const grant = await db.query<{
      id: string;
      created_at: string | Date;
      expires_at: string | Date;
      revoked_at: string | Date | null;
      max_per_order_usdc: string;
      max_total_usdc: string;
    }>(
      `SELECT id,created_at,expires_at,revoked_at,
              max_per_order_usdc::text,max_total_usdc::text
         FROM v2_agentic_grants
        WHERE user_id=$1::uuid AND provider='magic'
        ORDER BY created_at DESC LIMIT 1`,
      [userId],
    );
    return publicStatus(grant.rows[0], !!user.rows[0]?.wallet && !!user.rows[0]?.magic_issuer);
  });

  app.post("/v2/agentic/grant/prepare", {
    ...authenticate,
    config: { rateLimit: { max: 10, timeWindow: "1 hour" } },
  }, async (req: any, reply) => {
    const runtime = runtimeStatus();
    if (!runtime.ready) return reply.status(503).send({ error: runtime.reason });
    try {
      const userId = req.user.userId as string;
      const binding = await resolveMagicSolanaWalletBinding(db, userId);
      const policy = agenticConsentPolicy(process.env, LAZY_ENV);
      const signer = new AwsKmsAgenticDelegateSigner();
      const grant = prepareAgenticGrant({
        userId,
        wallet: binding.wallet,
        sessionDelegate: await signer.getPublicKey(),
        policy,
        nowSec: Math.floor(Date.now() / 1_000),
      });
      return {
        grant,
        message_base64: Buffer.from(solanaAgenticGrantBytes(grant)).toString("base64"),
        limits: {
          per_order_usdc: policy.maxPerOrderUsdcBaseUnits / 1_000_000,
          total_usdc: policy.maxTotalUsdcBaseUnits / 1_000_000,
          expires_at: new Date(grant.expiresAtSec * 1_000).toISOString(),
        },
      };
    } catch (error) {
      if (error instanceof AgenticAuthorizationError) {
        return reply.status(400).send({ error: error.message });
      }
      app.log.error({ err: error }, "v2 agentic grant preparation failed");
      return reply.status(503).send({ error: "Autosign service unavailable" });
    }
  });

  app.post("/v2/agentic/grant", {
    ...authenticate,
    config: { rateLimit: { max: 10, timeWindow: "1 hour" } },
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["grant", "grant_signature"],
        properties: {
          grant: { type: "object" },
          grant_signature: { type: "string", minLength: 1, maxLength: 88 },
        },
      },
    },
  }, async (req: any, reply) => {
    const runtime = runtimeStatus();
    if (!runtime.ready) return reply.status(503).send({ error: runtime.reason });
    try {
      const userId = req.user.userId as string;
      const binding = await resolveMagicSolanaWalletBinding(db, userId);
      const signer = new AwsKmsAgenticDelegateSigner();
      const grant = verifySolanaAgenticGrantSignature(
        req.body.grant,
        req.body.grant_signature,
      );
      assertAgenticGrantMatchesConsent({
        grant,
        userId,
        wallet: binding.wallet,
        sessionDelegate: await signer.getPublicKey(),
        policy: agenticConsentPolicy(process.env, LAZY_ENV),
        nowSec: Math.floor(Date.now() / 1_000),
      });
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        await activateExclusiveAgenticGrantInTransaction(
          client,
          { ...grant, spentUsdcBaseUnits: 0, revokedAtSec: null },
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
      return reply.status(201).send({ ok: true, grant_id: grant.id, expires_at: grant.expiresAtSec });
    } catch (error) {
      if (error instanceof AgenticAuthorizationError) {
        return reply.status(400).send({ error: error.message });
      }
      app.log.error({ err: error }, "v2 agentic grant persistence failed");
      return reply.status(503).send({ error: "Autosign service unavailable" });
    }
  });

  app.delete("/v2/agentic/grant", authenticate, async (req: any) => {
    const userId = req.user.userId as string;
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await revokeAllAgenticGrantsForUserInTransaction(client, userId, "magic");
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return { ok: true };
  });
}
