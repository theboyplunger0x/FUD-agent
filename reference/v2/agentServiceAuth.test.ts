import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import {
  AgentServiceAuthError,
  agentServiceSigningPayload,
  verifyAgentServiceRequest,
} from "./agentServiceAuth.js";

const secret = "0123456789abcdef0123456789abcdef";
const request = {
  serviceId: "fud-agent-beta",
  timestamp: 1_800_000_000,
  nonce: "12345678-1234-4123-8123-123456789abc",
  method: "POST",
  path: "/internal/agent/v1/actions",
  body: '{"version":1}',
};

function signature(body = request.body): string {
  return createHmac("sha256", secret)
    .update(agentServiceSigningPayload({ ...request, body }))
    .digest("hex");
}

test("accepts one exact fresh FUD-agent request", () => {
  assert.doesNotThrow(() => verifyAgentServiceRequest({
    expectedServiceId: request.serviceId,
    secret,
    headers: {
      serviceId: request.serviceId,
      timestamp: request.timestamp,
      nonce: request.nonce,
      signature: signature(),
    },
    method: request.method,
    path: request.path,
    body: request.body,
    nowSec: request.timestamp,
  }));
});

test("rejects tampering, stale timestamps and the wrong service", () => {
  const base = {
    expectedServiceId: request.serviceId,
    secret,
    headers: {
      serviceId: request.serviceId,
      timestamp: request.timestamp,
      nonce: request.nonce,
      signature: signature(),
    },
    method: request.method,
    path: request.path,
    body: request.body,
    nowSec: request.timestamp,
  };
  for (const operation of [
    () => verifyAgentServiceRequest({ ...base, body: "{}" }),
    () => verifyAgentServiceRequest({ ...base, nowSec: request.timestamp + 61 }),
    () => verifyAgentServiceRequest({ ...base, headers: { ...base.headers, serviceId: "attacker" } }),
  ]) {
    assert.throws(operation, (error: unknown) => error instanceof AgentServiceAuthError);
  }
});

