import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import {
  AgenticAuthorizationError,
  type AgenticAuthorizationProvider,
  type AgenticCapability,
  type AgenticChannel,
  type AgenticGrant,
  type AgenticV2Action,
  type VerifiedAgenticIntent,
} from "./agenticAuthorization.js";

const encoder = new TextEncoder();
const GRANT_DOMAIN = "FUD_V2_AGENTIC_GRANT_V1:";
const ACTION_DOMAIN = "FUD_V2_AGENTIC_ACTION_V1:";

export type SolanaAgenticGrantDefinitionV1 = Omit<
  AgenticGrant,
  "spentUsdcBaseUnits" | "revokedAtSec"
>;

export type SolanaAgenticActionPayloadV1 = {
  version: 1;
  grantId: string;
  userId: string;
  wallet: string;
  channel: AgenticChannel;
  externalIdentity: string;
  sourceEventId: string;
  nonce: string;
  action: AgenticV2Action;
};

export type SolanaAgenticEnvelopeV1 = {
  version: 1;
  grant: SolanaAgenticGrantDefinitionV1;
  /** Detached Ed25519 signature by grant.wallet, base64 encoded. */
  grantSignature: string;
  intent: SolanaAgenticActionPayloadV1;
  /** Detached Ed25519 signature by grant.sessionDelegate, base64 encoded. */
  intentSignature: string;
};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new AgenticAuthorizationError("bad_signed_payload");
  return encoded;
}

export function solanaAgenticGrantBytes(grant: SolanaAgenticGrantDefinitionV1): Uint8Array {
  return encoder.encode(`${GRANT_DOMAIN}${canonical(grant)}`);
}

export function solanaAgenticActionBytes(intent: SolanaAgenticActionPayloadV1): Uint8Array {
  return encoder.encode(`${ACTION_DOMAIN}${canonical(intent)}`);
}

function record(value: unknown, code = "bad_signed_envelope"): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AgenticAuthorizationError(code);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new AgenticAuthorizationError(code);
  }
}

function text(value: unknown, code: string, maxLength = 256): string {
  if (typeof value !== "string"
      || !value.trim()
      || value !== value.trim()
      || value.length > maxLength) {
    throw new AgenticAuthorizationError(code);
  }
  return value;
}

function safeInteger(value: unknown, code: string, positive = false): number {
  if (!Number.isSafeInteger(value) || (positive ? Number(value) <= 0 : Number(value) < 0)) {
    throw new AgenticAuthorizationError(code);
  }
  return Number(value);
}

function stringArray(value: unknown, allowed: ReadonlySet<string> | null, code: string): string[] {
  if (!Array.isArray(value)
      || value.length === 0
      || value.length > 256
      || value.some((entry) => (
        typeof entry !== "string"
        || !entry.trim()
        || entry !== entry.trim()
        || entry.length > 256
        || (allowed !== null && !allowed.has(entry))
      ))
      || new Set(value).size !== value.length) {
    throw new AgenticAuthorizationError(code);
  }
  return [...value];
}

function publicKey(value: unknown, code: string): string {
  const encoded = text(value, code);
  try {
    const key = new PublicKey(encoded);
    if (key.toBase58() !== encoded) throw new Error("non-canonical public key");
    return encoded;
  } catch {
    throw new AgenticAuthorizationError(code);
  }
}

function signature(value: unknown, code: string): Uint8Array {
  const encoded = text(value, code, 88);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new AgenticAuthorizationError(code);
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.length !== nacl.sign.signatureLength || decoded.toString("base64") !== encoded) {
    throw new AgenticAuthorizationError(code);
  }
  return decoded;
}

function parseGrant(value: unknown): SolanaAgenticGrantDefinitionV1 {
  const input = record(value, "bad_signed_grant");
  exactKeys(input, [
    "version", "id", "provider", "userId", "wallet", "chain", "sessionDelegate",
    "targetProgram", "environment", "audience", "allowedChannels", "allowedCapabilities",
    "allowedMarketIds", "maxPerOrderUsdcBaseUnits", "maxTotalUsdcBaseUnits", "expiresAtSec",
  ], "bad_signed_grant");
  if (input.version !== 1 || input.chain !== "solana") {
    throw new AgenticAuthorizationError("bad_signed_grant");
  }
  const marketIds = input.allowedMarketIds === null
    ? null
    : stringArray(input.allowedMarketIds, null, "bad_signed_grant");
  return {
    version: 1,
    id: text(input.id, "bad_signed_grant"),
    provider: text(input.provider, "bad_signed_grant"),
    userId: text(input.userId, "bad_signed_grant"),
    wallet: publicKey(input.wallet, "bad_grant_wallet"),
    chain: "solana",
    sessionDelegate: publicKey(input.sessionDelegate, "bad_session_delegate"),
    targetProgram: publicKey(input.targetProgram, "bad_target_program"),
    environment: text(input.environment, "bad_signed_grant"),
    audience: text(input.audience, "bad_signed_grant"),
    allowedChannels: stringArray(
      input.allowedChannels,
      new Set<AgenticChannel>(["x", "telegram"]),
      "bad_signed_grant",
    ) as AgenticChannel[],
    allowedCapabilities: stringArray(
      input.allowedCapabilities,
      new Set<AgenticCapability>(["order.place", "order.cancel"]),
      "bad_signed_grant",
    ) as AgenticCapability[],
    allowedMarketIds: marketIds,
    maxPerOrderUsdcBaseUnits: safeInteger(input.maxPerOrderUsdcBaseUnits, "bad_signed_grant", true),
    maxTotalUsdcBaseUnits: safeInteger(input.maxTotalUsdcBaseUnits, "bad_signed_grant", true),
    expiresAtSec: safeInteger(input.expiresAtSec, "bad_signed_grant", true),
  };
}

/** Verify the one-time wallet signature before a grant is persisted. */
export function verifySolanaAgenticGrantSignature(
  value: unknown,
  encodedSignature: unknown,
): SolanaAgenticGrantDefinitionV1 {
  const grant = parseGrant(value);
  const valid = nacl.sign.detached.verify(
    solanaAgenticGrantBytes(grant),
    signature(encodedSignature, "bad_grant_signature"),
    new PublicKey(grant.wallet).toBytes(),
  );
  if (!valid) throw new AgenticAuthorizationError("invalid_grant_signature");
  return grant;
}

function parseAction(value: unknown): AgenticV2Action {
  const input = record(value, "bad_signed_action");
  if (input.capability === "order.place") {
    exactKeys(input, [
      "capability", "marketId", "assetSide", "action", "limitPriceCents", "sharesCenti",
      "tif", "expiresAtSec", "idempotencyKey",
    ], "bad_signed_action");
    if (input.assetSide !== "long" && input.assetSide !== "short") {
      throw new AgenticAuthorizationError("bad_signed_action");
    }
    if (input.action !== "buy" && input.action !== "sell") {
      throw new AgenticAuthorizationError("bad_signed_action");
    }
    if (input.tif !== "gtc" && input.tif !== "ioc" && input.tif !== "gtd") {
      throw new AgenticAuthorizationError("bad_signed_action");
    }
    if (input.expiresAtSec !== null && !Number.isSafeInteger(input.expiresAtSec)) {
      throw new AgenticAuthorizationError("bad_signed_action");
    }
    return {
      capability: "order.place",
      marketId: text(input.marketId, "bad_signed_action"),
      assetSide: input.assetSide,
      action: input.action,
      limitPriceCents: safeInteger(input.limitPriceCents, "bad_signed_action", true),
      sharesCenti: safeInteger(input.sharesCenti, "bad_signed_action", true),
      tif: input.tif,
      expiresAtSec: input.expiresAtSec as number | null,
      idempotencyKey: text(input.idempotencyKey, "bad_signed_action"),
    };
  }
  if (input.capability === "order.cancel") {
    exactKeys(input, ["capability", "marketId", "orderId", "idempotencyKey"], "bad_signed_action");
    return {
      capability: "order.cancel",
      marketId: text(input.marketId, "bad_signed_action"),
      orderId: text(input.orderId, "bad_signed_action"),
      idempotencyKey: text(input.idempotencyKey, "bad_signed_action"),
    };
  }
  throw new AgenticAuthorizationError("bad_signed_action");
}

function parseIntent(value: unknown): SolanaAgenticActionPayloadV1 {
  const input = record(value, "bad_signed_intent");
  exactKeys(input, [
    "version", "grantId", "userId", "wallet", "channel", "externalIdentity",
    "sourceEventId", "nonce", "action",
  ], "bad_signed_intent");
  if (input.version !== 1 || (input.channel !== "x" && input.channel !== "telegram")) {
    throw new AgenticAuthorizationError("bad_signed_intent");
  }
  return {
    version: 1,
    grantId: text(input.grantId, "bad_signed_intent"),
    userId: text(input.userId, "bad_signed_intent"),
    wallet: publicKey(input.wallet, "bad_intent_wallet"),
    channel: input.channel,
    externalIdentity: text(input.externalIdentity, "bad_signed_intent"),
    sourceEventId: text(input.sourceEventId, "bad_signed_intent"),
    nonce: text(input.nonce, "bad_signed_intent"),
    action: parseAction(input.action),
  };
}

/**
 * Provider-neutral Ed25519 verifier for Solana embedded wallets. Magic (or a
 * later wallet provider) supplies signatures, while this adapter owns the FUD
 * domain separation and normalization contract.
 */
export class SolanaSessionAuthorizationProvider implements AgenticAuthorizationProvider {
  async verify(value: unknown): Promise<VerifiedAgenticIntent> {
    const envelope = record(value);
    exactKeys(
      envelope,
      ["version", "grant", "grantSignature", "intent", "intentSignature"],
      "bad_signed_envelope",
    );
    if (envelope.version !== 1) throw new AgenticAuthorizationError("unsupported_envelope_version");
    const grant = parseGrant(envelope.grant);
    const intent = parseIntent(envelope.intent);
    if (intent.grantId !== grant.id
        || intent.userId !== grant.userId
        || intent.wallet !== grant.wallet) {
      throw new AgenticAuthorizationError("signed_grant_intent_mismatch");
    }
    verifySolanaAgenticGrantSignature(grant, envelope.grantSignature);
    const validIntent = nacl.sign.detached.verify(
      solanaAgenticActionBytes(intent),
      signature(envelope.intentSignature, "bad_intent_signature"),
      new PublicKey(grant.sessionDelegate).toBytes(),
    );
    if (!validIntent) throw new AgenticAuthorizationError("invalid_intent_signature");
    return {
      grant: { ...grant, spentUsdcBaseUnits: 0, revokedAtSec: null },
      userId: intent.userId,
      wallet: intent.wallet,
      channel: intent.channel,
      externalIdentity: intent.externalIdentity,
      sourceEventId: intent.sourceEventId,
      nonce: intent.nonce,
      action: intent.action,
    };
  }
}
