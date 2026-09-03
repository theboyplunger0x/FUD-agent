import { randomUUID } from "node:crypto";
import type { AgentIntent, ChannelEvent } from "./domain.js";
import { signEngineRequest } from "./request-signing.js";

export type EngineActionRequest = {
  version: 1;
  identity: {
    channel: ChannelEvent["channel"];
    externalIdentity: string;
  };
  privateChat: boolean;
  sourceEventId: string;
  occurredAt: string;
  intent: AgentIntent;
};

export type EngineActionResult = {
  accepted: boolean;
  receiptId?: string;
  marketId?: string;
  orderId?: string;
  status?: string;
  message?: string;
};

export class FudEngineClient {
  constructor(private readonly config: {
    baseUrl: string;
    serviceId: string;
    sharedSecret: string;
    fetchImpl?: typeof fetch;
  }) {}

  async execute(event: ChannelEvent, intent: AgentIntent): Promise<EngineActionResult> {
    const path = "/internal/agent/v1/actions";
    const body = JSON.stringify({
      version: 1,
      identity: { channel: event.channel, externalIdentity: event.externalUserId },
      privateChat: event.privateChat,
      sourceEventId: event.sourceEventId,
      occurredAt: event.occurredAt,
      intent,
    } satisfies EngineActionRequest);
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = randomUUID();
    const signed = signEngineRequest({
      serviceId: this.config.serviceId,
      secret: this.config.sharedSecret,
      method: "POST",
      path,
      timestamp,
      nonce,
      body,
    });
    const response = await (this.config.fetchImpl ?? fetch)(new URL(path, this.config.baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json", ...signed },
      body,
      signal: AbortSignal.timeout(30_000),
    });
    const payload = await response.json().catch(() => ({})) as EngineActionResult & { error?: string };
    if (!response.ok) throw new Error(payload.error ?? payload.message ?? `FUD engine returned HTTP ${response.status}`);
    return payload;
  }
}

