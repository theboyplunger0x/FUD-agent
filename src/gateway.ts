import { parseCommand, validateChannelEvent, type ChannelEvent } from "./domain.js";
import type { FudEngineClient, EngineActionResult } from "./engine-client.js";

export class AgentGateway {
  constructor(private readonly engine: Pick<FudEngineClient, "execute">) {}

  async handle(event: ChannelEvent): Promise<EngineActionResult> {
    validateChannelEvent(event);
    const intent = parseCommand(event.text);
    return this.engine.execute(event, intent);
  }
}

