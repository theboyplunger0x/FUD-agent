import type { Queryable } from "./dbClient.js";

export type AgenticExternalIdentity =
  | { channel: "x"; externalId: string; username?: string | null }
  | { channel: "telegram"; externalId: string; username?: string | null };

export type ResolvedAgenticIdentity = {
  userId: string;
  channel: AgenticExternalIdentity["channel"];
  externalIdentity: string;
  username: string | null;
};

export class AgenticIdentityError extends Error {
  constructor(public readonly code: string, message = code) {
    super(message);
    this.name = "AgenticIdentityError";
  }
}

function normalizeNumericId(value: string, code: string): string {
  const normalized = value.trim();
  if (!/^\d{1,24}$/.test(normalized)) throw new AgenticIdentityError(code);
  return normalized;
}

/**
 * Resolve before parsing any value-moving text. X deliberately requires the
 * immutable provider id; a handle-only event is not accepted for V2 agentic use.
 */
export async function resolveAgenticIdentity(
  db: Queryable,
  identity: AgenticExternalIdentity,
): Promise<ResolvedAgenticIdentity> {
  const externalId = normalizeNumericId(identity.externalId, "bad_external_identity");
  const result = identity.channel === "x"
    ? await db.query<{ id: string; username: string | null; banned: boolean }>(
        `SELECT id,username,banned FROM users WHERE x_user_id=$1`,
        [externalId],
      )
    : await db.query<{ id: string; username: string | null; banned: boolean }>(
        `SELECT id,username,banned FROM users WHERE telegram_id=$1::bigint`,
        [externalId],
      );
  if (result.rows.length !== 1) throw new AgenticIdentityError("identity_not_linked");
  if (result.rows[0].banned) throw new AgenticIdentityError("identity_user_blocked");
  return {
    userId: result.rows[0].id,
    channel: identity.channel,
    externalIdentity: `${identity.channel}:${externalId}`,
    username: result.rows[0].username,
  };
}
