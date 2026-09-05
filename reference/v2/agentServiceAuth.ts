import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const SIGNING_DOMAIN = "FUD_AGENT_REQUEST_V1";

export type AgentServiceHeaders = {
  serviceId: string;
  timestamp: number;
  nonce: string;
  signature: string;
};

export class AgentServiceAuthError extends Error {
  constructor(public readonly code: string, message = code) {
    super(message);
    this.name = "AgentServiceAuthError";
  }
}

function bodyHash(body: string): string {
  return createHash("sha256").update(body).digest("hex");
}

export function agentServiceSigningPayload(input: {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
}): string {
  return [
    SIGNING_DOMAIN,
    input.method.toUpperCase(),
    input.path,
    String(input.timestamp),
    input.nonce,
    bodyHash(input.body),
  ].join("\n");
}

export function verifyAgentServiceRequest(input: {
  expectedServiceId: string;
  secret: string;
  headers: AgentServiceHeaders;
  method: string;
  path: string;
  body: string;
  nowSec?: number;
  maxSkewSeconds?: number;
}): void {
  if (!input.expectedServiceId.trim() || input.headers.serviceId !== input.expectedServiceId) {
    throw new AgentServiceAuthError("unknown_agent_service");
  }
  if (Buffer.byteLength(input.secret) < 32) {
    throw new AgentServiceAuthError("agent_service_not_configured");
  }
  if (!Number.isSafeInteger(input.headers.timestamp)) {
    throw new AgentServiceAuthError("bad_agent_timestamp");
  }
  const nowSec = input.nowSec ?? Math.floor(Date.now() / 1_000);
  const maxSkewSeconds = input.maxSkewSeconds ?? 60;
  if (Math.abs(nowSec - input.headers.timestamp) > maxSkewSeconds) {
    throw new AgentServiceAuthError("stale_agent_request");
  }
  if (!/^[0-9a-f]{64}$/i.test(input.headers.signature)) {
    throw new AgentServiceAuthError("bad_agent_signature");
  }
  if (!/^[0-9a-f-]{16,64}$/i.test(input.headers.nonce)) {
    throw new AgentServiceAuthError("bad_agent_nonce");
  }
  const expected = createHmac("sha256", input.secret)
    .update(agentServiceSigningPayload({
      method: input.method,
      path: input.path,
      timestamp: input.headers.timestamp,
      nonce: input.headers.nonce,
      body: input.body,
    }))
    .digest();
  const actual = Buffer.from(input.headers.signature, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new AgentServiceAuthError("bad_agent_signature");
  }
}

