import express, { type Request, type Response, type NextFunction } from "express";
import { postReplyViaSession, type PostReplyResult } from "./browser.js";
import { existsSync } from "node:fs";
import { mkdir, writeFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const PORT       = parseInt(process.env.PORT ?? "3030", 10);
const SECRET     = process.env.X_POSTER_SECRET;
const STATE_PATH = process.env.X_STATE_PATH ?? resolve(process.cwd(), "data", "x-state.json");

if (!SECRET) {
  console.error("[x-poster] FATAL: X_POSTER_SECRET env var is required");
  process.exit(1);
}

const app = express();
// 256kb supports both small request bodies and the X session state upload (~20kb today).
app.use(express.json({ limit: "256kb" }));

// ─── Auth middleware (skip for /health) ───────────────────────────────────────
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.path === "/health") return next();
  const auth = req.headers.authorization;
  if (auth !== `Bearer ${SECRET}`) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return;
  }
  next();
});

// ─── Idempotency cache (5 min TTL) ────────────────────────────────────────────
interface CachedResponse {
  result: PostReplyResult;
  ts:     number;
}
const idempotencyCache = new Map<string, CachedResponse>();
const IDEMPOTENCY_TTL  = 5 * 60 * 1000;

function pruneIdempotencyCache(): void {
  const now = Date.now();
  for (const [key, val] of idempotencyCache.entries()) {
    if (now - val.ts > IDEMPOTENCY_TTL) idempotencyCache.delete(key);
  }
}

// ─── Concurrency guard (1 in-flight reply at a time) ──────────────────────────
let inFlight    = 0;
let isShuttingDown = false;

// ─── Rate limiter (sliding window: 10 /reply per 60s) ─────────────────────────
const replyTimestamps: number[] = [];
const REPLY_WINDOW_MS = 60_000;
const REPLY_LIMIT     = 10;

function checkReplyRate(): boolean {
  const now    = Date.now();
  const cutoff = now - REPLY_WINDOW_MS;
  while (replyTimestamps.length > 0 && replyTimestamps[0] < cutoff) {
    replyTimestamps.shift();
  }
  if (replyTimestamps.length >= REPLY_LIMIT) return false;
  replyTimestamps.push(now);
  return true;
}

// ─── /health (public, minimal) ────────────────────────────────────────────────
app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true, uptime_s: Math.floor(process.uptime()) });
});

// ─── /admin/status (auth'd, detailed) ─────────────────────────────────────────
app.get("/admin/status", async (_req: Request, res: Response) => {
  let stateBytes = 0;
  let stateMtime: string | null = null;
  if (existsSync(STATE_PATH)) {
    try {
      const s = await stat(STATE_PATH);
      stateBytes = s.size;
      stateMtime = s.mtime.toISOString();
    } catch {}
  }
  res.json({
    ok:           true,
    uptime_s:     Math.floor(process.uptime()),
    state_exists: existsSync(STATE_PATH),
    state_bytes:  stateBytes,
    state_mtime:  stateMtime,
    in_flight:    inFlight,
  });
});

// ─── POST /admin/upload-state ─────────────────────────────────────────────────
// Uploads a Playwright storage state JSON (cookies + localStorage) to STATE_PATH.
// Auth via the same Bearer secret. Used to seed the Railway volume after first
// deploy and to refresh after re-login on the operator's local machine.
app.post("/admin/upload-state", async (req: Request, res: Response) => {
  const state = req.body;
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    res.status(400).json({ ok: false, error: "missing_or_invalid_state" });
    return;
  }
  // Sanity-check the shape: Playwright storage state has `cookies` (array) and `origins` (array)
  if (!Array.isArray((state as any).cookies) || !Array.isArray((state as any).origins)) {
    res.status(400).json({ ok: false, error: "invalid_state_shape" });
    return;
  }
  try {
    const stateDir = dirname(STATE_PATH);
    await mkdir(stateDir, { recursive: true });
    const json = JSON.stringify(state, null, 2);
    await writeFile(STATE_PATH, json, "utf-8");
    console.log(`[x-poster] state uploaded: ${json.length} bytes → ${STATE_PATH}`);
    res.json({ ok: true, bytes: json.length, path: STATE_PATH });
  } catch (e: any) {
    console.error("[x-poster] state upload failed:", e?.message ?? e);
    res.status(500).json({ ok: false, error: "write_failed" });
  }
});

// ─── POST /reply ──────────────────────────────────────────────────────────────
app.post("/reply", async (req: Request, res: Response) => {
  if (isShuttingDown) {
    res.status(503).json({ ok: false, error: "shutting_down" });
    return;
  }

  const { replyToId, text, idempotencyKey } = req.body ?? {};

  if (typeof replyToId !== "string" || !/^\d{15,20}$/.test(replyToId)) {
    res.status(400).json({ ok: false, error: "invalid_reply_to_id" });
    return;
  }
  if (typeof text !== "string" || text.trim().length === 0) {
    res.status(400).json({ ok: false, error: "empty_text" });
    return;
  }
  if (text.length > 280) {
    res.status(400).json({ ok: false, error: "text_too_long" });
    return;
  }
  if (typeof idempotencyKey === "string" && idempotencyKey.length > 128) {
    res.status(400).json({ ok: false, error: "idempotency_key_too_long" });
    return;
  }

  // Idempotency (replay cached response if same key was used recently)
  if (typeof idempotencyKey === "string" && idempotencyKey.length > 0) {
    pruneIdempotencyCache();
    const cached = idempotencyCache.get(idempotencyKey);
    if (cached) {
      res.json({ ...cached.result, idempotent_replay: true });
      return;
    }
  }

  // Reject if already busy — keeps it simple at low volume
  if (inFlight > 0) {
    res.status(429).json({ ok: false, error: "busy_retry_later" });
    return;
  }

  // Rate limit (sliding window) so even sequential abuse can't burn credits
  if (!checkReplyRate()) {
    res.status(429).json({ ok: false, error: "rate_limited", retry_after_s: 60 });
    return;
  }

  inFlight++;
  try {
    console.log(`[x-poster] /reply replyToId=${replyToId} text="${text.slice(0, 80)}"`);
    const result = await postReplyViaSession({
      statePath: STATE_PATH,
      replyToId,
      text,
      headed:    false,
    });
    console.log(`[x-poster] /reply result: ${JSON.stringify(result)}`);

    if (typeof idempotencyKey === "string" && idempotencyKey.length > 0) {
      idempotencyCache.set(idempotencyKey, { result, ts: Date.now() });
    }

    res.status(result.ok ? 200 : 500).json(result);
  } catch (e: any) {
    console.error("[x-poster] /reply unexpected error:", e?.message ?? e);
    res.status(500).json({ ok: false, error: `internal:${String(e?.message ?? e).slice(0, 200)}` });
  } finally {
    inFlight--;
  }
});

// ─── Process error handlers (don't crash on a stray rejection) ────────────────
process.on("unhandledRejection", (reason) => {
  console.error("[x-poster] unhandledRejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[x-poster] uncaughtException:", err?.message ?? err);
});

// ─── Graceful shutdown (drain in-flight, then close) ──────────────────────────
const server = app.listen(PORT, () => {
  console.log(`[x-poster] listening on :${PORT} (state=${STATE_PATH})`);
});

async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`[x-poster] received ${signal} — draining...`);
  // Stop accepting new connections
  server.close(() => console.log("[x-poster] http server closed"));
  // Wait for in-flight reply (max 30s)
  const deadline = Date.now() + 30_000;
  while (inFlight > 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 250));
  }
  if (inFlight > 0) {
    console.warn(`[x-poster] forced shutdown with ${inFlight} in-flight`);
  }
  process.exit(0);
}
process.on("SIGTERM", () => void gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => void gracefulShutdown("SIGINT"));
