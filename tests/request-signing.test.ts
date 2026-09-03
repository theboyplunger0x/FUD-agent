import assert from "node:assert/strict";
import test from "node:test";
import { signEngineRequest, verifyEngineRequest } from "../src/request-signing.js";

const secret = "0123456789abcdef0123456789abcdef";

test("signs and verifies one exact engine request", () => {
  const headers = signEngineRequest({
    serviceId: "test-agent",
    secret,
    method: "POST",
    path: "/internal/agent/v1/actions",
    timestamp: 1000,
    nonce: "nonce-1",
    body: "{\"hello\":\"world\"}",
  });
  assert.equal(verifyEngineRequest({
    secret,
    signature: headers["x-fud-agent-signature"],
    method: "POST",
    path: "/internal/agent/v1/actions",
    timestamp: 1000,
    nonce: "nonce-1",
    body: "{\"hello\":\"world\"}",
    now: 1000,
  }), true);
});

test("body/path changes and stale requests fail", () => {
  const headers = signEngineRequest({
    serviceId: "test-agent",
    secret,
    method: "POST",
    path: "/internal/agent/v1/actions",
    timestamp: 1000,
    nonce: "nonce-1",
    body: "{}",
  });
  const base = {
    secret,
    signature: headers["x-fud-agent-signature"],
    method: "POST",
    path: "/internal/agent/v1/actions",
    timestamp: 1000,
    nonce: "nonce-1",
    body: "{}",
    now: 1000,
  };
  assert.equal(verifyEngineRequest({ ...base, body: "{\"tampered\":true}" }), false);
  assert.equal(verifyEngineRequest({ ...base, path: "/other" }), false);
  assert.equal(verifyEngineRequest({ ...base, now: 2000 }), false);
});

