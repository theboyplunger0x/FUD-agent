import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import { LAZY_ENV } from "../services/lazyMarketService.js";
import {
  AgentGatewayActionError,
  agenticActionFromGatewayIntent,
  type AgentGatewayIntent,
} from "../v2/agentGatewayAction.js";
import {
  AgentServiceAuthError,
  verifyAgentServiceRequest,
} from "../v2/agentServiceAuth.js";
import { AgenticAuthorizationError } from "../v2/agenticAuthorization.js";
import {
  AwsKmsAgenticDelegateSigner,
  signSolanaAgenticIntent,
} from "../v2/agenticDelegateSigner.js";
import { agenticConsentPolicy } from "../v2/agenticGrantConsent.js";
import { executeAgenticV2Action } from "../v2/agenticExecution.js";
import { loadActiveAgenticGrantMaterial } from "../v2/agenticGrantStore.js";
import {
  AgenticIdentityError,
  resolveAgenticIdentity,
  type AgenticExternalIdentity,
} from "../v2/agenticIdentity.js";
import { resolveMagicSolanaWalletBinding } from "../v2/magicAgenticBinding.js";
import {
  SolanaSessionAuthorizationProvider,
  type SolanaAgenticActionPayloadV1,
} from "../v2/solanaAgenticProvider.js";

const ACTION_PATH = "/internal/agent/v1/actions";

type GatewayBody = {
  version: 1;
  identity: { channel: "x" | "telegram"; externalIdentity: string };
  privateChat: boolean;
  sourceEventId: string;
  occurredAt: string;
  intent: AgentGatewayIntent;
};

function header(value: string | string[] | undefined): string {
  return typeof value === "string" ? value : "";
}

function stableActionNonce(channel: "x" | "telegram", sourceEventId: string): string {
  return createHash("sha256").update(`${channel}\0${sourceEventId}`).digest("hex");
}

async function consumeServiceNonce(serviceId: string, nonce: string, timestamp: number): Promise<void> {
  const inserted = await db.query(
    `INSERT INTO v2_agent_service_nonces (service_id,nonce,request_timestamp)
     VALUES ($1,$2,$3::bigint)
     ON CONFLICT (service_id,nonce) DO NOTHING
     RETURNING nonce`,
    [serviceId, nonce, timestamp],
  );
  if (!inserted.rows[0]) throw new AgentServiceAuthError("agent_service_replay");
  // Bounded housekeeping. Business idempotency lives in v2_agentic_consumptions.
  await db.query(
    `DELETE FROM v2_agent_service_nonces WHERE created_at<clock_timestamp()-INTERVAL '10 minutes'`,
  );
}

function externalIdentity(body: GatewayBody): AgenticExternalIdentity {
  return body.identity.channel === "x"
    ? { channel: "x", externalId: body.identity.externalIdentity }
    : { channel: "telegram", externalId: body.identity.externalIdentity };
}

function statusFor(error: unknown): number {
  if (error instanceof AgentServiceAuthError) {
    return error.code === "agent_service_replay" ? 409 : 401;
  }
  if (error instanceof AgentGatewayActionError) return 422;
  if (error instanceof AgenticIdentityError || error instanceof AgenticAuthorizationError) return 403;
  return 503;
}

export async function registerV2AgentGatewayRoutes(app: FastifyInstance): Promise<void> {
  let signer: AwsKmsAgenticDelegateSigner | null = null;

  app.post<{ Body: GatewayBody }>(ACTION_PATH, {
    config: { rateLimit: { max: 120, timeWindow: "1 minute" } },
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["version", "identity", "privateChat", "sourceEventId", "occurredAt", "intent"],
        properties: {
          version: { const: 1 },
          identity: {
            type: "object",
            additionalProperties: false,
            required: ["channel", "externalIdentity"],
            properties: {
              channel: { enum: ["x", "telegram"] },
              externalIdentity: { type: "string", pattern: "^[0-9]{1,24}$" },
            },
          },
          privateChat: { type: "boolean" },
          sourceEventId: { type: "string", minLength: 1, maxLength: 256 },
          occurredAt: { type: "string", format: "date-time" },
          intent: {
            oneOf: [
              {
                type: "object",
                additionalProperties: false,
                required: ["kind", "token", "chain", "timeframe", "side", "amountUsdc"],
                properties: {
                  kind: { const: "market.open_with_position" },
                  token: { type: "string", minLength: 1, maxLength: 64 },
                  chain: { const: "SOL" },
                  timeframe: { enum: ["6h", "12h", "24h"] },
                  side: { enum: ["long", "short"] },
                  amountUsdc: { type: "number", exclusiveMinimum: 0, maximum: 100000 },
                  message: { type: "string", minLength: 1, maxLength: 140 },
                },
              },
              {
                type: "object",
                additionalProperties: false,
                required: ["kind", "marketId", "side", "amountUsdc"],
                properties: {
                  kind: { const: "order.place" },
                  marketId: { type: "string", minLength: 1, maxLength: 64 },
                  side: { enum: ["long", "short"] },
                  amountUsdc: { type: "number", exclusiveMinimum: 0, maximum: 100000 },
                  maxPriceCents: { type: "integer", minimum: 1, maximum: 99 },
                },
              },
              {
                type: "object",
                additionalProperties: false,
                required: ["kind", "marketId", "orderId"],
                properties: {
                  kind: { const: "order.cancel" },
                  marketId: { type: "string", minLength: 1, maxLength: 64 },
                  orderId: { type: "string", minLength: 1, maxLength: 64 },
                },
              },
            ],
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const serviceId = header(request.headers["x-fud-agent-id"]);
      const timestamp = Number(header(request.headers["x-fud-agent-timestamp"]));
      const nonce = header(request.headers["x-fud-agent-nonce"]);
      verifyAgentServiceRequest({
        expectedServiceId: process.env.FUD_AGENT_SERVICE_ID ?? "",
        secret: process.env.FUD_AGENT_SHARED_SECRET ?? "",
        headers: {
          serviceId,
          timestamp,
          nonce,
          signature: header(request.headers["x-fud-agent-signature"]),
        },
        method: "POST",
        path: ACTION_PATH,
        body: JSON.stringify(request.body),
      });
      await consumeServiceNonce(serviceId, nonce, timestamp);

      const identityInput = externalIdentity(request.body);
      const identity = await resolveAgenticIdentity(db, identityInput);
      const material = await loadActiveAgenticGrantMaterial(db, identity.userId);
      const action = agenticActionFromGatewayIntent({
        channel: request.body.identity.channel,
        sourceEventId: request.body.sourceEventId,
        intent: request.body.intent,
      });
      const intent: SolanaAgenticActionPayloadV1 = {
        version: 1,
        grantId: material.grant.id,
        userId: identity.userId,
        wallet: material.grant.wallet,
        channel: identity.channel,
        externalIdentity: identity.externalIdentity,
        sourceEventId: request.body.sourceEventId,
        nonce: stableActionNonce(identity.channel, request.body.sourceEventId),
        action,
      };
      signer ??= new AwsKmsAgenticDelegateSigner();
      const envelope = await signSolanaAgenticIntent({
        grant: material.grant,
        grantSignature: material.grantSignature,
        intent,
        signer,
      });
      const policy = agenticConsentPolicy(process.env, LAZY_ENV);
      const result = await executeAgenticV2Action(db, {
        identity: identityInput,
        privateChat: request.body.privateChat,
        envelope,
        action,
      }, {
        provider: new SolanaSessionAuthorizationProvider(),
        resolveWalletBinding: resolveMagicSolanaWalletBinding,
        targetProgram: policy.targetProgram,
        environment: policy.environment,
        audience: policy.audience,
      });
      return { accepted: true, status: result.capability, result };
    } catch (error) {
      const status = statusFor(error);
      const code = error instanceof AgentServiceAuthError
        || error instanceof AgentGatewayActionError
        || error instanceof AgenticIdentityError
        || error instanceof AgenticAuthorizationError
        ? error.code
        : "agent_execution_unavailable";
      if (status >= 500) request.log.error({ err: error }, "agent gateway execution failed");
      return reply.status(status).send({
        accepted: false,
        code,
        error: error instanceof Error ? error.message : "Agent execution unavailable",
      });
    }
  });
}

