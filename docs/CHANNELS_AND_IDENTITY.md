# Channels and identity map

This is the source-of-truth map for the social agent. It distinguishes reading
X, posting as `@FUDmarkets`, linking a user's X account and authorizing a trade.
Those are separate operations and must not be collapsed into one credential.

## X/Twitter: what runs in V1

### Read and discovery: twitterapi.io

`reference/v1/fud-bot/x.ts` uses `TWITTERAPI_KEY` for:

- `GET /twitter/user/mentions` — poll mentions of `@FUDmarkets`;
- `GET /twitter/tweets?tweet_ids=...` — load a tweet by ID/URL;
- `GET /twitter/user/last_tweets` — discover recent FUD tweets before polling
  their quote tweets;
- `GET /twitter/tweet/quotes` — poll quote tweets;
- `POST /twitter/user_login_v2`, `POST /twitter/user_login_v3`,
  `GET /twitter/get_my_x_account_detail_v3` and
  `POST /twitter/send_tweet_v3` — retained experimental session code.

The v2/v3 login and `send_tweet_v3` functions are dormant in the current
production path. They are not the active posting fallback.

### Reply posting: official X API

Replies to mentions are posted with the official X API using OAuth 1.0a:

- `POST https://api.twitter.com/2/tweets`;
- `POST https://upload.twitter.com/1.1/media/upload.json` for the optional bot
  card image.

The bot should use its own read/write application credentials:
`X_BOT_API_KEY`, `X_BOT_API_SECRET`, `X_BOT_ACCESS_TOKEN` and
`X_BOT_ACCESS_TOKEN_SECRET`. V1 falls back to the generic `X_API_*` variables
only for older environments. The extracted adapter should not keep that
fallback: user-linking and bot-posting applications have different privileges.

### Proactive reply fallback: x-poster

Proactive KOL replies are routed to the separate browser service through
`X_POSTER_URL` + `X_POSTER_SECRET`. The exact service is preserved at
`reference/v1/services/x-poster/`.

It exposes:

- public `GET /health`;
- authenticated `GET /admin/status`;
- authenticated `POST /admin/upload-state` for Playwright storage state;
- authenticated `POST /reply` with `replyToId`, `text` and optional
  `idempotencyKey`.

The storage-state JSON contains login cookies and is password-equivalent. It is
gitignored and must stay in the x-poster persistent volume, never in this repo.
Browser automation is a brittle fallback: selectors, session expiry and X terms
must be monitored. The official API remains preferred when it permits the post.

### User X account linking: FUDmarkets only

`reference/v1/routes/auth.ts` preserves the complete V1 auth route. The relevant
routes are:

- authenticated `GET /auth/x-auth-url` — creates an OAuth 1.0a request token and
  stores its secret for five minutes;
- public `GET /auth/x-callback` — exchanges the verifier, reads `v2.me()`, checks
  uniqueness and saves immutable `x_user_id` plus normalized `x_username`;
- authenticated `POST /auth/disconnect-x` — clears the link.

This flow uses the lower-privilege user-linking X application (`X_API_KEY` and
`X_API_SECRET`) and remains in FUDmarkets because only that backend may bind an
external identity to a FUD user. The social agent receives the stable provider
author ID on an event; it never writes `users.x_user_id` itself.

## Telegram: what runs in V1

`reference/v1/fud-bot/telegram.ts` contains the complete Telegraf interaction:

- token/contract search and price card;
- market-open wizard, side, amount, message and confirmation;
- live-market browsing and take-position flow;
- `/start`, `/link`, `/me`, `/markets`, `/challenges`, `/settings`;
- group-to-DM handoff for value-moving actions;
- admin approve/edit/reject controls for X drafts;
- configurable amount presets.

V1 uses direct PostgreSQL access and mints its own FUD JWT with `JWT_SECRET`.
That is intentionally forbidden in the extracted runtime. The active adapter
must verify Telegram, normalize `{chatId, userId, updateId}`, preserve the UX and
send typed actions through `FudEngineClient`.

Telegram linking remains canonical in FUDmarkets:

1. a short-lived record is created in `tg_link_tokens`;
2. the authenticated web user consumes the token;
3. FUDmarkets assigns `users.telegram_id` and `telegram_username`;
4. later social actions resolve that stable Telegram ID inside FUDmarkets.

## Authorization is separate from identity

An X OAuth link or Telegram link proves which FUD user produced an event. It
does not authorize unlimited movement of funds. For every action, FUDmarkets
must independently verify the user's active Magic/delegated grant, capability,
expiry, amount cap, daily cap and idempotency key before calling the V2 engine.

## Desired extracted request flow

```text
provider webhook/poller
  -> verify provider authenticity
  -> canonical source event ID + stable provider author ID
  -> deterministic parser (LLM output is untrusted input)
  -> FudEngineClient HMAC request
  -> FUDmarkets identity lookup + grant/cap/replay checks
  -> canonical V2 engine
  -> receipt returned to provider adapter
```

## Important non-features

- `postV3()` existing in the snapshot does not mean twitterapi.io is the current
  production fallback.
- X/Telegram account linking does not equal autosign consent.
- The reference files are evidence and migration input; they are excluded from
  the active build and do not form a standalone bot process.
