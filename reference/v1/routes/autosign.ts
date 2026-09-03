// Bot autosign consent endpoints.
//
// Two-state model: a user either has an active consent or doesn't.
// No per-trade caps, no daily caps, no expiration — vault balance is
// the natural ceiling (user can't lose more than they deposited), and
// AUTOSIGN_ENABLED is our kill switch.
//
// A hard per-trade ceiling against LLM hallucination lives in the
// autosign service code, not exposed as user-configurable.
//
//   POST   /autosign/consent  → enable autosign for this user
//   DELETE /autosign/consent  → revoke
//   GET    /autosign/status   → fetch state

import { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import { getUserDelegatedWallet, PrivyConfigError, PrivyRpcError } from "../services/privyClient.js";

export async function autosignRoutes(app: FastifyInstance) {
  // ── POST /autosign/consent ──
  // Body: just { privy_user_id }. We resolve everything else (wallet
  // address, Privy wallet_id) SERVER-SIDE by querying Privy directly.
  // The client used to send wallet_address + (embedded as any).id but
  // that's untrusted and the wallet_id was unreliable — Codex 2026-05-12.
  app.post("/autosign/consent", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const user = (req as any).user;
    const { privy_user_id } = req.body as any;

    if (typeof privy_user_id !== "string" || !privy_user_id.startsWith("did:privy:")) {
      return reply.status(400).send({ error: "privy_user_id required (did:privy:...)" });
    }

    // Resolve the delegated wallet authoritatively from Privy. This
    // also acts as a server-side proof that the user actually executed
    // delegateWallet() — if no delegation exists at Privy, no consent
    // is recorded.
    let delegated;
    try {
      delegated = await getUserDelegatedWallet(privy_user_id);
    } catch (e: any) {
      if (e instanceof PrivyConfigError) {
        return reply.status(503).send({ error: "Autosign not configured on server. Try again later." });
      }
      if (e instanceof PrivyRpcError) {
        return reply.status(502).send({ error: `Privy lookup failed: ${e.status}` });
      }
      return reply.status(500).send({ error: "Unexpected error verifying delegation" });
    }
    if (!delegated) {
      return reply.status(412).send({ error: "No delegated wallet found at Privy. Run delegation first." });
    }

    // Wallet binding sanity check against users.wallet_address. The
    // wallet that was delegated MUST match the user's vault wallet,
    // otherwise signatures wouldn't be accepted at bet time anyway.
    const { rows: [dbUser] } = await db.query(
      `SELECT wallet_address FROM users WHERE id = $1`,
      [user.userId],
    );
    if (dbUser?.wallet_address && dbUser.wallet_address.toLowerCase() !== delegated.address.toLowerCase()) {
      return reply.status(409).send({ error: "Delegated wallet doesn't match your vault wallet" });
    }

    // UPSERT — re-consent clears any previous revocation.
    await db.query(
      `INSERT INTO bot_autosign_consents
         (user_id, privy_user_id, wallet_address, privy_wallet_id,
          revoked_at, updated_at)
       VALUES ($1, $2, $3, $4, NULL, NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET privy_user_id   = EXCLUDED.privy_user_id,
             wallet_address  = EXCLUDED.wallet_address,
             privy_wallet_id = EXCLUDED.privy_wallet_id,
             revoked_at      = NULL,
             updated_at      = NOW()`,
      [user.userId, privy_user_id, delegated.address, delegated.walletId],
    );

    return reply.send({ ok: true, wallet_address: delegated.address });
  });

  // ── DELETE /autosign/consent ──
  app.delete("/autosign/consent", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const user = (req as any).user;
    await db.query(
      `UPDATE bot_autosign_consents
          SET revoked_at = NOW(), updated_at = NOW()
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [user.userId],
    );
    return reply.send({ ok: true });
  });

  // ── GET /autosign/status ──
  // active        = user has granted consent in our DB
  // runtime_ready = server-side runtime can actually autosign (feature
  //                 flag on + Privy creds present). UI should distinguish
  //                 between "consent granted" and "operationally usable"
  //                 so we never tell the user autosign is on while the
  //                 backend silently falls back to web (Codex 2026-05-12).
  app.get("/autosign/status", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const user = (req as any).user;
    // runtime_ready must include PRIVY_AUTHORIZATION_KEY (Codex 2026-05-12):
    // without it, server-side signing fails with 'missing privy-authorization-
    // signature' even though Basic auth (app_id/secret) is valid. UI would
    // otherwise enable autosign while every bot bet silently fails.
    const runtime_ready =
      process.env.AUTOSIGN_ENABLED === "1"
      && !!process.env.PRIVY_APP_ID
      && !!process.env.PRIVY_APP_SECRET
      && !!process.env.PRIVY_AUTHORIZATION_KEY;
    const { rows: [c] } = await db.query(
      `SELECT created_at, revoked_at FROM bot_autosign_consents WHERE user_id = $1`,
      [user.userId],
    );
    if (!c) return reply.send({ active: false, runtime_ready });
    return reply.send({
      active:     c.revoked_at === null,
      runtime_ready,
      created_at: c.created_at,
      revoked_at: c.revoked_at,
    });
  });
}
