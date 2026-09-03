import Fastify from "fastify";
import { AgentGateway } from "./gateway.js";
import { FudEngineClient } from "./engine-client.js";
import { IntentParseError, type ChannelEvent } from "./domain.js";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function buildServer(options?: { engine?: FudEngineClient }) {
  const app = Fastify({ logger: true, bodyLimit: 64 * 1024 });
  const engine = options?.engine ?? new FudEngineClient({
    baseUrl: required("FUD_ENGINE_URL"),
    serviceId: required("FUD_AGENT_SERVICE_ID"),
    sharedSecret: required("FUD_AGENT_SHARED_SECRET"),
  });
  const gateway = new AgentGateway(engine);

  app.get("/health", async () => ({ ok: true, service: "fud-agent", version: 1 }));

  // Provider adapters should normalize signed Telegram/X events into this
  // internal shape. Never expose this route publicly without an authenticated
  // ingress/proxy: provider-specific webhook verification is the next adapter.
  app.post<{ Body: ChannelEvent }>("/events", async (request, reply) => {
    try {
      return await gateway.handle(request.body);
    } catch (error) {
      if (error instanceof IntentParseError) {
        return reply.status(400).send({ error: error.message, code: error.code });
      }
      request.log.error({ err: error }, "agent event failed");
      return reply.status(502).send({ error: error instanceof Error ? error.message : "Agent event failed" });
    }
  });
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const app = buildServer();
  const port = Number(process.env.PORT ?? "3100");
  await app.listen({ host: "0.0.0.0", port });
}

