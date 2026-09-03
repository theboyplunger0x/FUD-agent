import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export type SignedRequestHeaders = {
  "x-fud-agent-id": string;
  "x-fud-agent-timestamp": string;
  "x-fud-agent-nonce": string;
  "x-fud-agent-signature": string;
};

export function bodyHash(body: string): string {
  return createHash("sha256").update(body).digest("hex");
}

export function requestSigningPayload(input: {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
}): string {
  return [
    "FUD_AGENT_REQUEST_V1",
    input.method.toUpperCase(),
    input.path,
    String(input.timestamp),
    input.nonce,
    bodyHash(input.body),
  ].join("\n");
}

export function signEngineRequest(input: {
  serviceId: string;
  secret: string;
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
}): SignedRequestHeaders {
  if (Buffer.byteLength(input.secret) < 32) throw new Error("FUD_AGENT_SHARED_SECRET must be at least 32 bytes");
  const payload = requestSigningPayload(input);
  const signature = createHmac("sha256", input.secret).update(payload).digest("hex");
  return {
    "x-fud-agent-id": input.serviceId,
    "x-fud-agent-timestamp": String(input.timestamp),
    "x-fud-agent-nonce": input.nonce,
    "x-fud-agent-signature": signature,
  };
}

export function verifyEngineRequest(input: {
  secret: string;
  signature: string;
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
  now?: number;
  maxSkewSeconds?: number;
}): boolean {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const maxSkew = input.maxSkewSeconds ?? 60;
  if (!Number.isSafeInteger(input.timestamp) || Math.abs(now - input.timestamp) > maxSkew) return false;
  if (!/^[0-9a-f]{64}$/i.test(input.signature)) return false;
  const expected = createHmac("sha256", input.secret)
    .update(requestSigningPayload(input))
    .digest();
  const actual = Buffer.from(input.signature, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

