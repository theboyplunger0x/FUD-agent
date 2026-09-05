import { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { verifyPrivyToken } from "../lib/privyVerifier.js";
import {
  attachUnmatchedCreatorRallyRowsForXHandle,
  claimRallyDistributionsForUser,
} from "../services/seasonCreatorReconciler.js";

// ─── OAuth single-use exchange codes ─────────────────────────────────────────
// Short-lived (60s) one-time codes that the OAuth callback hands back
// to the frontend in place of putting the JWT directly in the redirect
// URL. The frontend POSTs the code to /auth/exchange to get the JWT in
// the response body — out-of-band of any URL, so browser history /
// referer / analytics never see the bearer.
//
// Backed by `oauth_exchange_codes` (Postgres). Survives restarts and
// works across replicas. The raw code only exists in the redirect URL
// and the FE; the DB stores SHA-256(code) so a leaked DB dump doesn't
// expose unconsumed codes. Single-use is enforced atomically via
// DELETE ... RETURNING in `consumeOAuthCode` — two concurrent exchanges
// of the same code can never both succeed.
const OAUTH_CODE_TTL_MS = 60_000;

function hashCode(code: string): string {
  return crypto.createHash("sha256").update(code).digest("hex");
}

// fable-5-execution (Auth HIGH-1 — session revocation): mint a user JWT that
// carries the user's current token_version as the `tv` claim. The authenticate
// decorator (index.ts) rejects a token whose `tv` no longer matches the DB, so a
// password reset / logout (which bump token_version) invalidate every outstanding
// token for that user. Fetches token_version fresh at sign time (auth ops are
// infrequent), so callers don't need to SELECT it themselves.
export async function signUserToken(app: any, userId: string, username: string): Promise<string> {
  const { rows: [row] } = await db.query<{ token_version: number }>(
    `SELECT token_version FROM users WHERE id = $1`, [userId],
  );
  return app.jwt.sign(
    { userId, username, tv: row?.token_version ?? 0 },
    { expiresIn: "7d" },
  );
}

async function storeOAuthCode(code: string, jwt: string) {
  const expiresAt = new Date(Date.now() + OAUTH_CODE_TTL_MS);
  // Opportunistic prune of expired rows.
  await db.query(`DELETE FROM oauth_exchange_codes WHERE expires_at < NOW()`);
  await db.query(
    `INSERT INTO oauth_exchange_codes (code_hash, jwt, expires_at) VALUES ($1, $2, $3)`,
    [hashCode(code), jwt, expiresAt],
  );
}

async function consumeOAuthCode(code: string): Promise<string | null> {
  const { rows: [row] } = await db.query<{ jwt: string; expires_at: Date }>(
    `DELETE FROM oauth_exchange_codes
       WHERE code_hash = $1
       RETURNING jwt, expires_at`,
    [hashCode(code)],
  );
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  return row.jwt;
}
import nodemailer from "nodemailer";
import { TwitterApi } from "twitter-api-v2";

// ─── Email transporter (lazy-init) ───────────────────────────────────────────

function getMailer() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT ?? "587"),
    secure: process.env.SMTP_PORT === "465",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

// ─── Routes ──────────────────────────────────────────────────────────────────

export async function authRoutes(app: FastifyInstance) {

  // POST /auth/register — 10 attempts / 15 min per IP
  app.post("/auth/register", {
    config: { rateLimit: { max: 10, timeWindow: "15 minutes" } },
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["username", "password"],
        properties: {
          username:      { type: "string", minLength: 3, maxLength: 30 },
          password:      { type: "string", minLength: 6, maxLength: 128 },
          email:         { type: "string", maxLength: 254 },
          referral_code: { type: "string", maxLength: 50 },
        },
      },
    },
  }, async (req, reply) => {
    const { username, password, email, referral_code } = req.body as any;

    if (!username || !password) {
      return reply.status(400).send({ error: "username and password required" });
    }
    if (username.length < 3) {
      return reply.status(400).send({ error: "Username must be at least 3 characters" });
    }
    if (password.length < 6) {
      return reply.status(400).send({ error: "Password must be at least 6 characters" });
    }

    const { rows: existing } = await db.query(
      `SELECT id FROM users WHERE username = $1`, [username.toLowerCase()]
    );
    if (existing.length > 0) {
      return reply.status(409).send({ error: "Username already taken" });
    }

    if (email) {
      const { rows: emailTaken } = await db.query(
        `SELECT id FROM users WHERE email = $1`, [email.toLowerCase()]
      );
      if (emailTaken.length > 0) {
        return reply.status(409).send({ error: "Email already in use" });
      }
    }

    // Validate referral code if provided
    let referredBy: string | null = null;
    if (referral_code) {
      const code = String(referral_code).trim().toUpperCase();
      const { rows: [referrer] } = await db.query(
        `SELECT id, username FROM users WHERE referral_code = $1`, [code]
      );
      if (!referrer) {
        return reply.status(400).send({ error: "Invalid referral code" });
      }
      // Prevent self-referral by email match
      if (email && referrer.username === username.toLowerCase()) {
        return reply.status(400).send({ error: "You can't use your own referral code" });
      }
      referredBy = referrer.id;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const refCode = crypto.randomBytes(4).toString("hex").toUpperCase();

    const { rows: [user] } = await db.query(
      `INSERT INTO users (username, password_hash, email, referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, balance_usd, wallet_address, has_connected_wallet, is_market_maker, is_official, created_at`,
      [username.toLowerCase(), passwordHash, email ? email.toLowerCase() : null, refCode, referredBy]
    );

    const token = await signUserToken(app, user.id, user.username);
    return reply.status(201).send({
      token,
      user,
      referral: { applied: !!referredBy, code: referral_code?.trim()?.toUpperCase() ?? null },
    });
  });

  // POST /auth/login — 10 attempts / 15 min per IP (brute-force protection)
  app.post("/auth/login", {
    config: { rateLimit: { max: 10, timeWindow: "15 minutes" } },
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["username", "password"],
        properties: {
          username: { type: "string", minLength: 1, maxLength: 254 },
          password: { type: "string", minLength: 1, maxLength: 128 },
        },
      },
    },
  }, async (req, reply) => {
    const { username, password } = req.body as any;

    if (!username || !password) {
      return reply.status(400).send({ error: "username/email and password required" });
    }

    // Accept email or username
    const isEmail = username.includes("@");
    const { rows: [user] } = await db.query(
      isEmail
        ? `SELECT id, username, password_hash, balance_usd, wallet_address, has_connected_wallet, tier, is_market_maker, is_official, x_username, telegram_username, discord_username, discord_id, avatar_url, bio FROM users WHERE email = $1`
        : `SELECT id, username, password_hash, balance_usd, wallet_address, has_connected_wallet, tier, is_market_maker, is_official, x_username, telegram_username, discord_username, discord_id, avatar_url, bio FROM users WHERE username = $1`,
      [username.toLowerCase()]
    );

    if (!user || !user.password_hash) {
      return reply.status(401).send({ error: "Invalid username or password" });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return reply.status(401).send({ error: "Invalid username or password" });
    }

    const token = await signUserToken(app, user.id, user.username);
    return { token, user: { id: user.id, username: user.username, balance_usd: user.balance_usd, wallet_address: user.wallet_address, has_connected_wallet: user.has_connected_wallet, tier: user.tier ?? "", is_market_maker: user.is_market_maker, is_official: user.is_official, x_username: user.x_username, telegram_username: user.telegram_username, discord_username: user.discord_username, discord_id: user.discord_id, avatar_url: user.avatar_url, bio: user.bio } };
  });

  // POST /auth/logout — server-side session revocation (Auth HIGH-1).
  // Bumps token_version so EVERY outstanding JWT for this user (including the one
  // making this call) stops verifying. The client also drops its localStorage token.
  app.post("/auth/logout", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const { userId } = (req as any).user;
    await db.query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [userId]);
    return { ok: true };
  });

  // GET /auth/me
  app.get("/auth/me", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const { userId } = (req as any).user;
    const { rows: [user] } = await db.query(
      // /auth/me returns the FULL avatar_url (including data: payloads) so
       // the user can see their own profile picture. The public profile route
       // (/users/:username) and search route strip data: avatars to save
       // bandwidth on other-user views — but stripping here was wrong: it
       // made new PFP uploads disappear on the very next page load because
       // /auth/me returned NULL for the data: URL we just stored. 2026-05-15.
      `SELECT id, username, balance_usd, wallet_address,
        magic_wallet_address_evm, solana_wallet_address,
        has_connected_wallet, tier, is_market_maker, is_official, created_at,
        x_username, telegram_username, discord_username, discord_id,
        avatar_url, bio, privy_user_id
        FROM users WHERE id = $1`, [userId]
    );
    if (!user) return reply.status(404).send({ error: "User not found" });

    // Metrics/retention touchpoint. Fire-and-forget so /auth/me remains fast
    // and a transient DB write cannot block session restore.
    void db.query(`UPDATE users SET last_seen_at = NOW() WHERE id = $1`, [userId])
      .catch((e: any) => req.log.warn({ err: e, userId }, "[auth/me] last_seen_at update failed"));

    // Lazy wallet backfill: bootstrap retries (4×750ms) exhaust before
    // Privy provisions the embedded wallet for slow signups. We saw the
    // last 5 signups today land with wallet_address=NULL → the user
    // gets stuck at "Set up your account to trade" because both DB
    // and (sometimes) client-side walletAddr are empty. /auth/me is
    // called on every session restore, so backfill here when we have
    // a privy_user_id but no wallet. Marcos 2026-05-13.
    if (!user.wallet_address && user.privy_user_id) {
      try {
        const { getUserEmbeddedWallet } = await import("../services/privyClient.js");
        const embedded = await getUserEmbeddedWallet(user.privy_user_id);
        if (embedded?.address) {
          const addr = embedded.address.toLowerCase();
          const { rows: [taken] } = await db.query(
            `SELECT id FROM users WHERE wallet_address = $1 AND id != $2`, [addr, userId]
          );
          if (!taken) {
            await db.query(
              `UPDATE users SET wallet_address = $1, has_connected_wallet = true WHERE id = $2`,
              [addr, userId],
            );
            user.wallet_address = addr;
            user.has_connected_wallet = true;
            app.log.info({ userId }, "backfilled wallet_address from Privy");
          }
        }
      } catch (e: any) {
        // Soft-fail — /auth/me must keep working even if Privy is down.
        app.log.warn({ err: e, userId }, "Privy wallet backfill failed");
      }
    }
    // Strip privy_user_id from response — it's only needed for the
    // backfill and shouldn't leak in /auth/me.
    delete user.privy_user_id;
    return user;
  });

  // /auth/paper-credit and /auth/testnet-credit removed in v21
  // (2026-05-04). Paper mode and the GenLayer testnet rail were both
  // retired pre-mainnet. Testnet now mirrors mainnet via FUDVault on
  // Sepolia — no more parallel rails.

  // POST /auth/link-wallet — backfill wallet_address when bootstrap
  // missed it. SECURITY: requires a verified Privy token containing
  // the wallet in `linked_accounts`. Without that proof, an
  // authenticated user could claim any unlinked address as theirs
  // and break attribution downstream (Codex P1).
  //
  // Privy's `linked_accounts` claim is server-signed inside the JWT,
  // so the client can't forge it. Membership proves Privy attested
  // the user actually controls the wallet (either embedded — Privy
  // created it — or external connected via the Privy auth flow).
  app.post("/auth/link-wallet", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const { userId } = (req as any).user;
    const { wallet_address, privy_token } = req.body as { wallet_address?: string; privy_token?: string };
    if (!wallet_address || typeof wallet_address !== "string") {
      return reply.status(400).send({ error: "wallet_address required" });
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(wallet_address)) {
      return reply.status(400).send({ error: "Invalid wallet address" });
    }
    if (!privy_token || typeof privy_token !== "string") {
      return reply.status(400).send({ error: "privy_token required (proof of wallet ownership)" });
    }
    const addr = wallet_address.toLowerCase();

    // Verify Privy token + the user it represents matches our session.
    let verified;
    try {
      verified = await verifyPrivyToken(privy_token);
    } catch (e: any) {
      return reply.status(401).send({ error: `Invalid Privy token: ${e.message}` });
    }
    const { rows: [u] } = await db.query<{ privy_user_id: string | null }>(
      `SELECT privy_user_id FROM users WHERE id = $1`, [userId],
    );
    if (!u?.privy_user_id || u.privy_user_id !== verified.userId) {
      return reply.status(403).send({ error: "Privy token does not match this account" });
    }

    // Wallet must appear in the Privy-attested linked_accounts list.
    const linked = (verified.wallets ?? []).find(w =>
      w.type === "wallet" &&
      typeof w.address === "string" &&
      w.address.toLowerCase() === addr,
    );
    if (!linked) {
      return reply.status(403).send({
        error: "Wallet not linked in Privy. Link it via Privy first, then try again.",
      });
    }

    // Atomic bind: only sets wallet_address when currently NULL (so we
    // never overwrite an existing binding) AND relies on the partial UNIQUE
    // index `idx_users_wallet_address_unique` to prevent two accounts from
    // racing onto the same wallet (Codex P1 / TOCTOU). The single statement
    // closes the read-check-update window the previous three-query path had.
    try {
      const { rows: [updated] } = await db.query<{ wallet_address: string }>(
        `UPDATE users SET wallet_address = $1, has_connected_wallet = true
           WHERE id = $2 AND wallet_address IS NULL
         RETURNING wallet_address`,
        [addr, userId],
      );
      if (updated) {
        return { wallet_address: updated.wallet_address, has_connected_wallet: true };
      }
      // No row updated → wallet_address was already set. Read and return it.
      const { rows: [existing] } = await db.query<{ wallet_address: string | null }>(
        `SELECT wallet_address FROM users WHERE id = $1`, [userId],
      );
      if (existing?.wallet_address) {
        return { wallet_address: existing.wallet_address, has_connected_wallet: true };
      }
      // Should be unreachable — request was authenticated so the user exists.
      return reply.status(404).send({ error: "User not found" });
    } catch (e: any) {
      // 23505 = unique_violation on idx_users_wallet_address_unique
      if (e?.code === "23505") {
        return reply.status(409).send({ error: "Wallet already linked to another account" });
      }
      throw e;
    }
  });

  // GET /auth/google/callback
  app.get("/auth/google/callback", async (req, reply) => {
    const oauth2 = (app as any).googleOAuth2;
    if (!oauth2) {
      return reply.status(503).send({ error: "Google OAuth not configured" });
    }

    let token: any;
    try {
      token = await oauth2.getAccessTokenFromAuthorizationCodeFlow(req, reply);
    } catch (err: any) {
      return reply.redirect(`${process.env.FRONTEND_URL ?? "http://localhost:3000"}/?auth_error=oauth_failed`);
    }

    // Fetch Google user info
    const googleRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${token.token.access_token}` },
    });
    const gUser = await googleRes.json() as { id: string; email: string; name: string; picture?: string };

    // Find or create user
    let { rows: [user] } = await db.query(
      `SELECT id, username, balance_usd FROM users WHERE google_id = $1`,
      [gUser.id]
    );

    if (!user && gUser.email) {
      // Maybe they registered by email before
      const { rows: [byEmail] } = await db.query(
        `SELECT id, username, balance_usd FROM users WHERE email = $1`,
        [gUser.email.toLowerCase()]
      );
      if (byEmail) {
        // Link google_id to existing account
        await db.query(`UPDATE users SET google_id = $1 WHERE id = $2`, [gUser.id, byEmail.id]);
        user = byEmail;
      }
    }

    if (!user) {
      // Create new account — derive a username from their Google name
      const base = gUser.name.toLowerCase().replace(/[^a-z0-9]/g, "_").slice(0, 18);
      let username = base;
      let suffix = 1;
      while (true) {
        const { rows } = await db.query(`SELECT id FROM users WHERE username = $1`, [username]);
        if (rows.length === 0) break;
        username = `${base}_${suffix++}`;
      }

      const { rows: [newUser] } = await db.query(
        `INSERT INTO users (username, email, google_id)
         VALUES ($1, $2, $3)
         RETURNING id, username, balance_usd`,
        [username, gUser.email?.toLowerCase() ?? null, gUser.id]
      );
      user = newUser;
    }

    const jwt = await signUserToken(app, user.id, user.username);

    // SECURITY (Codex P1, fixed 2026-05-08): never put the JWT in the
    // redirect URL. URLs leak through browser history, referer
    // headers, server access logs, third-party analytics, error
    // trackers — any one of those exposes the bearer to a passive
    // observer. Issue a short-lived single-use exchange code instead;
    // the frontend POSTs it to /auth/exchange to get the JWT in the
    // response body (out-of-band of the URL).
    const code = crypto.randomBytes(24).toString("hex");
    await storeOAuthCode(code, jwt);
    const frontendUrl = process.env.FRONTEND_URL ?? "http://localhost:3000";
    return reply.redirect(`${frontendUrl}/auth/callback?code=${code}`);
  });

  // POST /auth/exchange — convert OAuth callback code into a session
  // JWT. Single-use, 60s expiry. Body-only response so the JWT never
  // touches a URL.
  app.post("/auth/exchange", { config: { rateLimit: { max: 10, timeWindow: "5 minutes" } } }, async (req, reply) => {
    const { code } = req.body as { code?: string };
    if (!code || typeof code !== "string") {
      return reply.status(400).send({ error: "code required" });
    }
    const jwt = await consumeOAuthCode(code);
    if (!jwt) {
      return reply.status(400).send({ error: "Invalid or expired code" });
    }
    return { token: jwt };
  });

  // POST /auth/admin-login — exchange the master ADMIN_SECRET for a
  // short-lived JWT carrying `role: "admin"`. Once issued, the admin
  // surface accepts this token via `Authorization: Bearer ...`, so the
  // master secret no longer has to live in the browser. Rate-limited
  // tightly to slow brute-force attempts on the secret.
  app.post("/auth/admin-login",
    { config: { rateLimit: { max: 3, timeWindow: "15 minutes" } } },
    async (req, reply) => {
      const ADMIN_SECRET = process.env.ADMIN_SECRET ?? "";
      if (!ADMIN_SECRET) {
        return reply.status(503).send({ error: "Admin not configured" });
      }
      const { secret } = (req.body ?? {}) as { secret?: string };
      if (typeof secret !== "string" || secret.length === 0) {
        return reply.status(400).send({ error: "secret required" });
      }
      const a = Buffer.from(secret);
      const b = Buffer.from(ADMIN_SECRET);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return reply.status(401).send({ error: "Invalid admin secret" });
      }
      // No userId — admin sessions don't map to a user account today.
      // The presence of `role: "admin"` is what the admin preHandler
      // checks. Other auth paths set userId/username instead.
      // TTL is intentionally short: 7d (the user-session default) is
      // too long for a credential that grants full admin access with
      // no revocation table. 8h forces a re-login per workday.
      const token = await (app as any).jwt.sign({ role: "admin", jti: crypto.randomUUID() }, { expiresIn: "8h" });
      return { token };
    },
  );

  // POST /auth/forgot-password — 5 / 15 min (email enumeration + spam protection)
  app.post("/auth/forgot-password", { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } }, async (req, reply) => {
    const { email, username } = req.body as any;
    if (!email && !username) return reply.status(400).send({ error: "email or username required" });

    // Look up by email OR username — whichever was provided
    const { rows: [user] } = await db.query(
      `SELECT id, username, email FROM users WHERE email = $1 OR username = $2`,
      [email ? email.toLowerCase() : null, username ? username.toLowerCase() : null]
    );

    // SECURITY (Codex P2, fixed 2026-05-08): always return the same
    // 200 body whether the lookup hit, missed, or hit-but-no-email.
    // The earlier "No email linked" 400 leaked username existence —
    // an attacker could enumerate valid usernames + their auth method.
    // Now: silently no-op on no-email-linked accounts. Honest users
    // hit the email-add flow elsewhere; attackers get no signal.
    if (!user || !user.email) return { ok: true };

    // Generate a strong token, store its SHA-256 hash (Codex P2). The
    // raw token is never persisted — a DB read or backup leak now only
    // exposes hashes, useless without the original token. The token
    // itself ships in the email link; user submits it back, we hash
    // and compare.
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    await db.query(
      `UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '1 hour' WHERE id = $2`,
      [tokenHash, user.id]
    );
    // The link uses the raw token — only the user receiving the email
    // ever sees it.
    const resetToken = rawToken;

    const frontendUrl = process.env.FRONTEND_URL ?? "http://localhost:3000";
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;

    try {
      const mailer = getMailer();
      await mailer.sendMail({
        from: process.env.SMTP_FROM ?? "FUD.markets <noreply@fud.markets>",
        to: user.email,
        subject: "Reset your FUD.markets password",
        html: `
          <div style="font-family:monospace;background:#111;color:#fff;padding:32px;border-radius:12px;max-width:480px">
            <h2 style="margin:0 0 8px">FUD.markets</h2>
            <p style="color:#aaa;margin:0 0 24px">Password reset requested for <b>${user.username}</b></p>
            <a href="${resetLink}" style="display:inline-block;background:#fff;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:900;font-size:13px">
              Reset Password
            </a>
            <p style="color:#555;font-size:11px;margin-top:24px">Link expires in 1 hour. If you didn't request this, ignore this email.</p>
          </div>
        `,
      });
    } catch (err) {
      app.log.error({ err }, "failed to send reset email");
      // Still return 200 to not leak info
    }

    return { ok: true };
  });

  // POST /auth/reset-password
  app.post("/auth/reset-password", { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } }, async (req, reply) => {
    const { token, password } = req.body as any;
    if (!token || !password) {
      return reply.status(400).send({ error: "token and password required" });
    }
    if (password.length < 6) {
      return reply.status(400).send({ error: "Password must be at least 6 characters" });
    }

    // The DB stores SHA-256(token), never the raw token. Hash the
    // submitted token and compare. (Codex P2 fix 2026-05-08.)
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const { rows: [user] } = await db.query(
      `SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()`,
      [tokenHash]
    );
    if (!user) {
      return reply.status(400).send({ error: "Invalid or expired reset link" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await db.query(
      // fable-5-execution (Auth HIGH-1): bump token_version so every JWT issued
      // before this reset stops verifying — a stolen/old token can't survive the
      // victim's password reset.
      `UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL,
              token_version = token_version + 1 WHERE id = $2`,
      [passwordHash, user.id]
    );

    return { ok: true };
  });

  // POST /auth/wallet — DEPRECATED: authentication now handled via Privy (/api/users/bootstrap)
  app.post("/auth/wallet", { config: { rateLimit: { max: 30, timeWindow: "5 minutes" } } }, async (req, reply) => {
    return reply.status(410).send({ error: "Deprecated. Use Privy authentication (/api/users/bootstrap)." });
  });

  // POST /auth/link-telegram  { token }
  app.post("/auth/link-telegram", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const { token } = req.body as any;
    if (!token) return reply.status(400).send({ error: "token required" });

    const { rows: [entry] } = await db.query(
      `DELETE FROM tg_link_tokens WHERE token = $1 AND expires_at > NOW() RETURNING tg_id`,
      [token]
    );
    if (!entry) return reply.status(400).send({ error: "Token expired or invalid. Open /start in the bot again." });

    const userId = (req as any).user.userId;
    await db.query(`UPDATE users SET telegram_id = NULL WHERE telegram_id = $1`, [entry.tg_id]);
    await db.query(`UPDATE users SET telegram_id = $1 WHERE id = $2`, [entry.tg_id, userId]);

    const botToken = process.env.BOT_TOKEN;
    if (botToken) {
      fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: entry.tg_id,
          text: "✅ Telegram connected! You can now trade directly from the bot.",
        }),
      }).catch(() => {});
    }

    return { ok: true };
  });

  // GET /auth/x-auth-url — generate X OAuth URL for the logged-in user
  app.get("/auth/x-auth-url", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    // Block if already connected — connections are permanent
    const { rows: [existing] } = await db.query(`SELECT x_username FROM users WHERE id = $1`, [userId]);
    if (existing?.x_username) return reply.status(409).send({ error: "X account already connected" });
    const frontendUrl = process.env.FRONTEND_URL ?? "https://fud.markets";
    const callbackUrl = `${frontendUrl}/auth/callback`;
    const client      = new TwitterApi({ appKey: process.env.X_API_KEY!, appSecret: process.env.X_API_SECRET! });
    const { url, oauth_token, oauth_token_secret } = await client.generateAuthLink(callbackUrl, { linkMode: "authorize" });
    // Store oauth_token_secret temporarily (5 min)
    await db.query(
      `INSERT INTO x_oauth_tokens (oauth_token, oauth_token_secret, user_id, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')
       ON CONFLICT (oauth_token) DO UPDATE SET oauth_token_secret = $2, user_id = $3, expires_at = NOW() + INTERVAL '5 minutes'`,
      [oauth_token, oauth_token_secret, userId]
    );
    return { url };
  });

  // GET /auth/x-callback — exchange OAuth verifier for access token, save x_username
  app.get("/auth/x-callback", async (req, reply) => {
    const { oauth_token, oauth_verifier } = req.query as any;
    if (!oauth_token || !oauth_verifier) return reply.status(400).send({ error: "Missing OAuth params" });
    const { rows: [entry] } = await db.query(
      `DELETE FROM x_oauth_tokens WHERE oauth_token = $1 AND expires_at > NOW() RETURNING oauth_token_secret, user_id`,
      [oauth_token]
    );
    if (!entry) return reply.status(400).send({ error: "OAuth token expired or invalid" });
    const client   = new TwitterApi({ appKey: process.env.X_API_KEY!, appSecret: process.env.X_API_SECRET!, accessToken: oauth_token, accessSecret: entry.oauth_token_secret });
    const { client: userClient, screenName } = await client.login(oauth_verifier);
    const xUser    = await userClient.v2.me();
    const xUserId = xUser.data.id;
    const xUsername = xUser.data.username.toLowerCase();
    // Check not taken by another user
    const { rows: [taken] } = await db.query(
      `SELECT id FROM users WHERE (x_user_id = $1 OR x_username = $2) AND id != $3`,
      [xUserId, xUsername, entry.user_id]
    );
    if (taken) {
      const frontendUrl = process.env.FRONTEND_URL ?? "https://fud.markets";
      return reply.redirect(`${frontendUrl}/auth/callback?auth_error=already_linked`);
    }
    await db.query(
      `UPDATE users SET x_user_id = $1, x_username = $2 WHERE id = $3`,
      [xUserId, xUsername, entry.user_id],
    );
    attachUnmatchedCreatorRallyRowsForXHandle({
      userId: entry.user_id,
      xHandle: xUsername,
      trigger: "x_callback",
    })
      .then((r) => {
        if (r.attachedRows > 0) {
          app.log.info({
            userId: entry.user_id,
            xUsername,
            attachedRows: r.attachedRows,
            rawScore: r.rawScore,
          }, "attached Rally creator rows from X callback");
        }
      })
      .catch((e) => {
        app.log.warn({ err: e, userId: entry.user_id, xUsername }, "Rally creator attach failed from X callback");
      });
    // v71: Claim Rally Creator distribution rows (campaign archive table).
    // Additive to the legacy ledger-only attach above — the two paths use
    // distinct source_ref prefixes ('rally_<campaign>_<handle>' vs raw
    // '<handle>') so they never compete on the partial UNIQUE index.
    claimRallyDistributionsForUser({
      userId: entry.user_id,
      xHandle: xUsername,
      trigger: "x_callback",
    })
      .then((r) => {
        if (r.claimedRows > 0) {
          app.log.info({
            userId: entry.user_id,
            xUsername,
            claimedRows: r.claimedRows,
            ledgerRowsInserted: r.ledgerRowsInserted,
            rawScore: r.rawScore,
          }, "claimed Rally distribution rows from X callback");
        }
      })
      .catch((e) => {
        app.log.warn({ err: e, userId: entry.user_id, xUsername }, "Rally distribution claim failed from X callback");
      });
    const frontendUrl = process.env.FRONTEND_URL ?? "https://fud.markets";
    return reply.redirect(`${frontendUrl}/auth/callback?x_connected=1&x_username=${encodeURIComponent(xUsername)}`);
  });

  // POST /auth/disconnect-x — unlink X account
  app.post("/auth/disconnect-x", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    await db.query(`UPDATE users SET x_user_id = NULL, x_username = NULL WHERE id = $1`, [userId]);
    return { ok: true };
  });

  // POST /auth/disconnect-telegram — unlink Telegram account
  app.post("/auth/disconnect-telegram", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    await db.query(`UPDATE users SET telegram_id = NULL, telegram_username = NULL WHERE id = $1`, [userId]);
    return { ok: true };
  });

  // ─── Discord OAuth2 (verified handle connect) ───────────────────────────────
  // Mirrors the X flow but OAuth2 authorization-code. The Discord callback hits
  // the BACKEND directly (no JWT on that request), so user identity is carried
  // in a single-use `state` row (5min TTL). Gated on env config so the route is
  // a clean 503 until the Discord app secrets are provisioned.

  // GET /auth/discord-auth-url — build the authorize URL for the logged-in user
  app.get("/auth/discord-auth-url", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    const clientId    = process.env.DISCORD_CLIENT_ID;
    const redirectUri = process.env.DISCORD_REDIRECT_URI;
    if (!clientId || !redirectUri) {
      return reply.status(503).send({ error: "Discord connect not configured" });
    }
    // Block if already connected — connections are permanent (parity with X).
    // Gate on discord_id (immutable snowflake), NOT discord_username (a mutable
    // display name) — the stable key is the source of truth for "is it linked".
    const { rows: [existing] } = await db.query(`SELECT discord_id FROM users WHERE id = $1`, [userId]);
    if (existing?.discord_id) return reply.status(409).send({ error: "Discord account already connected" });

    const state = crypto.randomBytes(16).toString("hex");
    // Prune expired rows + clear any prior pending state for this user so a
    // double-click doesn't leave orphan rows lingering until TTL.
    await db.query(`DELETE FROM discord_oauth_states WHERE expires_at < NOW() OR user_id = $1`, [userId]);
    await db.query(
      `INSERT INTO discord_oauth_states (state, user_id, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '5 minutes')`,
      [state, userId],
    );
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "identify",
      state,
      prompt: "consent",
    });
    return { url: `https://discord.com/oauth2/authorize?${params.toString()}` };
  });

  // GET /auth/discord-callback — exchange code, save discord handle, bounce to FE
  app.get("/auth/discord-callback", async (req, reply) => {
    const frontendUrl = process.env.FRONTEND_URL ?? "https://fud.markets";
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code || !state) return reply.redirect(`${frontendUrl}/auth/callback?auth_error=discord_failed`);

    // Validate config BEFORE consuming the single-use state row — a
    // misconfigured pod must not burn the user's identity with no retry path.
    const clientId     = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri  = process.env.DISCORD_REDIRECT_URI;
    if (!clientId || !clientSecret || !redirectUri) {
      return reply.redirect(`${frontendUrl}/auth/callback?auth_error=discord_failed`);
    }

    // Single-use consume of the state row → identifies the user.
    const { rows: [entry] } = await db.query<{ user_id: string }>(
      `DELETE FROM discord_oauth_states WHERE state = $1 AND expires_at > NOW() RETURNING user_id`,
      [state],
    );
    if (!entry) return reply.redirect(`${frontendUrl}/auth/callback?auth_error=discord_failed`);

    try {
      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "authorization_code",
          code: String(code),
          redirect_uri: redirectUri,
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (!tokenRes.ok) throw new Error(`token exchange ${tokenRes.status}`);
      const tokenJson = await tokenRes.json() as { access_token?: string; token_type?: string };
      if (!tokenJson.access_token) throw new Error("no access_token");

      const meRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: `${tokenJson.token_type ?? "Bearer"} ${tokenJson.access_token}` },
        signal: AbortSignal.timeout(8000),
      });
      if (!meRes.ok) throw new Error(`me ${meRes.status}`);
      const me = await meRes.json() as { id?: string; username?: string; global_name?: string | null };
      if (!me.id || !me.username) throw new Error("malformed discord profile");

      const discordId       = me.id;
      // Validate the snowflake shape before it's stored + later embedded in a
      // discord.com/users/<id> profile link on the FE (closes any malformed-id path).
      if (!/^\d{17,20}$/.test(discordId)) throw new Error("malformed discord id");
      // Store the unique Discord username (handle), NOT the display name —
      // parity with the X @handle. Trim + non-empty guard.
      const discordUsername = (me.username || "").trim();
      if (!discordUsername) throw new Error("empty discord username");

      // Block if this Discord account is already linked to a different FUD user.
      const { rows: [taken] } = await db.query(
        `SELECT id FROM users WHERE discord_id = $1 AND id != $2`, [discordId, entry.user_id],
      );
      if (taken) return reply.redirect(`${frontendUrl}/auth/callback?auth_error=already_linked`);

      // Atomic link: `AND discord_id IS NULL` ensures only the first writer
      // lands if the same user races two concurrent connects. 0 rows → already
      // linked between the gate check and here.
      const upd = await db.query(
        `UPDATE users SET discord_id = $1, discord_username = $2 WHERE id = $3 AND discord_id IS NULL`,
        [discordId, discordUsername, entry.user_id],
      );
      if (upd.rowCount === 0) return reply.redirect(`${frontendUrl}/auth/callback?auth_error=already_linked`);
      return reply.redirect(`${frontendUrl}/auth/callback?discord_connected=1&discord_username=${encodeURIComponent(discordUsername)}`);
    } catch (e: any) {
      app.log.warn({ err: e, userId: entry.user_id }, "Discord OAuth callback failed");
      return reply.redirect(`${frontendUrl}/auth/callback?auth_error=discord_failed`);
    }
  });

  // POST /auth/disconnect-discord — unlink Discord account
  app.post("/auth/disconnect-discord", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    await db.query(`UPDATE users SET discord_id = NULL, discord_username = NULL WHERE id = $1`, [userId]);
    return { ok: true };
  });

  // POST /auth/tg-init-link — frontend generates a token so user can link via bot deep link
  app.post("/auth/tg-init-link", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    const token = crypto.randomBytes(16).toString("hex");
    await db.query(
      `INSERT INTO tg_link_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
      [token, userId]
    );
    return { token };
  });

  // POST /auth/update-profile — update avatar and bio
  // Avatar semantics: empty-string ('') is treated as "no change" so that
  // clients which seed the editor from the stripped public profile (where
  // base64 avatars come back as NULL) can post bio-only edits without
  // wiping the stored avatar. To actually clear an avatar a caller must
  // send `null`. Bio is updated as long as it is provided.
  app.post("/auth/update-profile", { preHandler: [(app as any).authenticate] }, async (req, reply) => {
    const userId = (req as any).user.userId;
    const { avatar_url, bio } = req.body as any;
    // Avatar validation: accept only a data:image/(jpeg|png|webp|gif) base64
    // payload (blocks SVG + non-image data: → no stored-XSS via the avatar
    // endpoint) or an http(s) URL. Keep the size cap on base64 payloads.
    if (typeof avatar_url === "string" && avatar_url !== "") {
      const v = avatar_url.trim();
      if (v.startsWith("data:")) {
        if (!/^data:image\/(jpeg|jpg|png|webp|gif);base64,/.test(v)) {
          return reply.status(400).send({ error: "Unsupported image type. Use JPEG, PNG, WebP or GIF." });
        }
        if (v.length > 100_000) {
          return reply.status(400).send({ error: "Avatar too large — please use a smaller image." });
        }
      } else if (!/^https?:\/\//i.test(v)) {
        return reply.status(400).send({ error: "Invalid avatar URL." });
      }
    }
    if (typeof bio === "string" && bio.length > 500) {
      return reply.status(400).send({ error: "Bio must be 500 characters or fewer." });
    }
    const touchAvatar = avatar_url !== undefined && avatar_url !== "";
    if (touchAvatar) {
      await db.query(
        `UPDATE users SET avatar_url = $1, bio = $2 WHERE id = $3`,
        [avatar_url, bio ?? null, userId]
      );
    } else {
      await db.query(
        `UPDATE users SET bio = $1 WHERE id = $2`,
        [bio ?? null, userId]
      );
    }
    // Return the FULL avatar_url (not stripped) — this is the owner's own
    // profile, they need to see their picture they just uploaded.
    const { rows: [updated] } = await db.query(
      `SELECT id, username, balance_usd, tier, x_username, telegram_username, discord_username, discord_id, avatar_url, bio
       FROM users WHERE id = $1`,
      [userId]
    );
    return updated;
  });
}
