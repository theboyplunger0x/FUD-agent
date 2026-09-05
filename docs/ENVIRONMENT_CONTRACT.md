# Environment contract

No values belong in this document or in Git. It records variable names,
ownership and purpose so an operator can configure each service without sharing
unrelated power with the agent.

## Active isolated gateway

| Variable | Owner | Purpose |
| --- | --- | --- |
| `NODE_ENV`, `PORT` | FUD-agent | Runtime configuration |
| `FUD_ENGINE_URL` | FUD-agent | Canonical FUDmarkets backend URL |
| `FUD_AGENT_SERVICE_ID` | both services | Identifies this agent service |
| `FUD_AGENT_SHARED_SECRET` | both services | Dedicated HMAC secret, at least 32 random bytes |

## Telegram adapter

| Variable | Purpose |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API credential for the extracted adapter |
| `TELEGRAM_WEBHOOK_SECRET` | Authenticates Telegram webhook delivery |
| `ADMIN_TG_ID`, `ADMIN_TG_ID_2` | Optional approval destinations for X drafts |

The V1 snapshot calls this token `BOT_TOKEN`. New active code should use
`TELEGRAM_BOT_TOKEN` and avoid carrying the ambiguous legacy name forward.

## X adapter

| Variable | Purpose |
| --- | --- |
| `TWITTERAPI_KEY` | twitterapi.io read/discovery calls |
| `X_WEBHOOK_SECRET` | Verifies X webhook ingress if webhooks replace polling |
| `X_BOT_API_KEY`, `X_BOT_API_SECRET` | Official X bot application's consumer credentials |
| `X_BOT_ACCESS_TOKEN`, `X_BOT_ACCESS_TOKEN_SECRET` | Official `@FUDmarkets` posting credentials |
| `X_POSTER_URL`, `X_POSTER_SECRET` | Optional authenticated browser-session fallback |
| `X_MENTION_POLL_MS` | Mention poll cadence; V1 enforces a 60-second minimum |
| `X_QUOTES_ENABLED`, `X_QUOTE_POLL_MS` | Quote polling switch and cadence |
| `X_REPLY_AGENT_ENABLED` | Enables generated reply drafting |
| `ENABLE_PROACTIVE_REPLIES` | Explicit gate for proactive posting commands |
| `BOT_REPLY_MEDIA_URL` | Optional image attached to official API replies |
| `ANTHROPIC_API_KEY` | Optional drafting only; never authorizes an action |

## x-poster service only

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port |
| `X_POSTER_SECRET` | Bearer authentication for every route except health |
| `X_STATE_PATH` | Persistent Playwright session-state path |

The local storage-state JSON is deliberately not represented by an environment
value and must never be committed.

## FUDmarkets-only variables

These appear in the V1 reference or related backend but must never be added to
the active FUD-agent runtime:

- `DATABASE_URL` and database credentials;
- `JWT_SECRET`;
- Magic secret/admin credentials and OIDC provider configuration;
- Privy credentials retained for legacy accounts;
- treasury/operator/delegate private keys, mnemonics or AWS KMS signing access;
- RPC write credentials that can act as the canonical executor.

The generic `X_API_KEY` and `X_API_SECRET` also stay in FUDmarkets for user OAuth
linking. The extracted bot uses the separate `X_BOT_*` application.

## Legacy snapshot variables

The read-only V1 code additionally references these names:

`BACKEND_URL`, `FRONTEND_URL`, `BOT_TOKEN`, `JWT_SECRET`, `FUD_PHASE`,
`BOT_COOKIE_ENCRYPTION_KEY`, `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`,
`X_ACCESS_TOKEN_SECRET`, `X_TWITTER_USERNAME`, `X_TWITTER_PASSWORD`,
`X_TWITTER_EMAIL`, `X_TWITTER_TOTP_SECRET` and `X_PROXY_URL`.

They document historical behavior. Do not blindly copy them into a new
deployment. In particular, the legacy cookie-login code and direct JWT minting
should be deleted as adapters move into active `src/`.
