# FUD.markets Bots — Full Context

> Two bots integrated into the FUD.markets backend: Telegram Bot + X (Twitter) Agent.
> Both live in `backend/src/fud-bot/` and run as part of the main backend process.

---

## Architecture

Both bots are started in `backend/src/index.ts`:
```typescript
import { startBot, startXAgent } from "./fud-bot/index.js";
startBot();      // Telegram
startXAgent();   // X/Twitter
```

They share the same PostgreSQL database and can call backend API endpoints directly via `fetch("http://localhost:3001/...")`.

### Files
```
backend/src/fud-bot/
  index.ts       → Exports startBot() and startXAgent()
  telegram.ts    → Telegraf-based Telegram bot (~500 lines)
  x.ts           → Twitter/X agent — polls mentions, generates replies with Claude, posts via OAuth (~400 lines)
```

---

## 1. Telegram Bot (`telegram.ts`)

### What it does
- Users can search tokens, open markets, place bets — all from Telegram
- Works in DMs and groups (inline mode)
- Handles account creation/linking
- Full trade flow: search → pick mode (real/paper) → timeframe → side → amount → message → confirm

### Key Features
- **Token search**: User sends a ticker/CA → bot fetches from DexScreener → shows price card
- **Trade flow**: Step-by-step inline keyboard (mode → timeframe → side → amount → message)
- **Account linking**: `/start link_{token}` links Telegram to existing web account
- **Auto-registration**: New users pick a username via chat
- **Group support**: Search in groups, open markets, share trade cards
- **Bet presets**: Customizable quick amounts per user (default: $5, $25, $100, $500)
- **X Agent admin**: Approve/edit/reject AI-generated X replies from Telegram

### Session Management
```typescript
// In-memory sessions: tgId → { token, userId, username }
const sessions = new Map<number, { token: string; userId: string; username: string }>();
```
Sessions are rebuilt from DB on each interaction (checks `users.telegram_id`).

### Trade State Machine
```typescript
interface PendingTrade {
  symbol, chain, ca, price, liquidity, volume24h, marketCap, name,
  mode?: "real" | "paper",
  timeframe?: string,
  side?: string,
  amount?: number,
  awaitingMsg?: boolean,    // waiting for tagline
  flowMsgId?: number,       // message to edit
  groupChatId?: number,     // post card to group after
}
```

### API Integration
Uses internal fetch to backend:
```typescript
async function apiFetch(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API}${path}`, { ...opts, headers: { "Content-Type": "application/json", ...opts.headers } });
  // ...
}
```

### Auth
Mints JWT tokens directly (same secret as backend):
```typescript
function mintToken(userId: string, username: string): string {
  const secret = process.env.JWT_SECRET!;
  // HMAC-SHA256 JWT
}
```

### Environment Variables
- `BOT_TOKEN` — Telegraf bot token
- `BACKEND_URL` — API base (default: http://localhost:3001)
- `FRONTEND_URL` — Web app URL (default: https://fud-markets.vercel.app)
- `JWT_SECRET` — For minting auth tokens
- `ANTHROPIC_API_KEY` — For Claude AI (used in X agent integration)

---

## 2. X/Twitter Agent (`x.ts`)

### What it does
- Polls @FUDmarkets mentions every ~60 seconds
- Uses Claude AI to generate contextual replies about crypto/memecoins
- Posts replies via Twitter API v2 (OAuth 1.0a)
- Admin approval flow via Telegram: AI generates reply → admin approves/edits/rejects

### Mention Polling
Uses twitterapi.io to fetch mentions:
```
GET https://api.twitterapi.io/twitter/user/last_tweets?userName=FUDmarkets
```
Filters for mentions since last poll time (`lastPollTime` stored in DB via `bot_kv` table).

### AI Reply Generation
Uses Claude (Anthropic SDK) to generate replies:
```typescript
const anthropic = new Anthropic();
// Generates contextual crypto replies based on the mention content
```

### Posting Methods
Two posting methods:
1. **OAuth 1.0a** (Twitter API v2) — `POST https://api.twitter.com/2/tweets` with HMAC-SHA1 signature
2. **twitterapi.io v3** — Server-side session posting (fallback)

### Admin Flow (via Telegram)
1. Mention detected → Claude generates reply
2. Reply sent to admin Telegram chat with buttons: [✅ Approve] [✏️ Edit] [❌ Reject]
3. Admin approves → bot posts to Twitter
4. Admin edits → types custom reply → bot posts that instead
5. Admin rejects → skipped

### Cookie/Session Management
Twitter cookies stored in DB (`bot_kv` table) for persistent sessions:
```sql
INSERT INTO bot_kv (key, value) VALUES ('x_login_cookies', $1)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
```

### Environment Variables
- `TWITTERAPI_KEY` — twitterapi.io API key (for mention polling + v3 posting)
- `X_API_KEY` — Twitter OAuth consumer key
- `X_API_SECRET` — Twitter OAuth consumer secret
- `X_ACCESS_TOKEN` — Twitter OAuth access token
- `X_ACCESS_TOKEN_SECRET` — Twitter OAuth access token secret
- `X_TWITTER_USERNAME` — @FUDmarkets
- `X_TWITTER_PASSWORD` — For cookie-based login
- `X_TWITTER_EMAIL` — For cookie-based login
- `X_TWITTER_TOTP_SECRET` — Optional 2FA
- `X_PROXY_URL` — Optional proxy for Twitter requests
- `ADMIN_TG_ID` — Telegram chat ID for admin (receives pending replies)
- `ADMIN_TG_ID_2` — Optional second admin
- `ANTHROPIC_API_KEY` — For Claude AI reply generation

---

## Database Tables Used by Bots

### `bot_kv` (key-value store)
```sql
CREATE TABLE IF NOT EXISTS bot_kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```
Used for: `x_login_cookies`, `lastPollTime`

### `tg_link_tokens` (Telegram account linking)
```sql
CREATE TABLE IF NOT EXISTS tg_link_tokens (
  token      TEXT PRIMARY KEY,
  tg_id      BIGINT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
```

### `users` columns used
- `telegram_id BIGINT UNIQUE` — Links Telegram account to FUD user
- `x_username` — Linked X/Twitter handle

---

## Current State / Known Issues

1. **X Agent is running** but polling shows 0 mentions consistently — may need to check if the @FUDmarkets account has recent mentions
2. **Solana deposit poller** gets 429 rate-limited frequently (noisy but not critical)
3. **Telegram bot works** — users can search tokens, open markets, bet from Telegram
4. **X posting** uses both OAuth 1.0a (preferred) and twitterapi.io v3 (fallback)
5. **Admin approval** for X replies works via Telegram inline keyboards

---

## How to Test

### Telegram Bot
1. Open https://t.me/FUDmarkets_BOT
2. Send any ticker (e.g. "PEPE") or CA
3. Follow the trade flow

### X Agent
- Mention @FUDmarkets on Twitter
- Wait for polling cycle (~60s)
- Admin receives reply proposal in Telegram
- Approve to post

### Logs
```bash
# All bot logs
cd backend && railway logs --filter "bot OR x-agent"

# Just X agent
railway logs --filter "x-agent"

# Just Telegram
railway logs --filter "bot"
```
