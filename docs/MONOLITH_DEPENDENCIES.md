# V1 monolith dependency map

The reference bots are exact snapshots, not independently runnable modules.
Their recursive import graph reaches 43 FUDmarkets files because V1 can talk to
the database, wallets, vaults, pricing/oracles and chain execution directly.
That is the coupling this extraction is designed to remove.

## Direct dependencies

### Telegram

- `db/client` — sessions, registration, Telegram links and bot state;
- `fud-bot/x` — X approval/edit/reject administration;
- `botGuards` — token bans, metadata validation, vault/rate checks;
- `tokenIdentity` — canonical safe token/ticker display;
- `autosignService` — direct lazy market/take/bet execution;
- `lazyMarketService` — legacy lazy-market environment;
- `lib/market` — fee and timeframe definitions.

### X

- `db/client` — identity lookup, poll cursor, drafts and cooldown records;
- `botGuards` — market-creation rules and token safety;
- `tokenIdentity` — token display normalization;
- `autosignService` — direct autosign execution;
- `lib/market` — timeframe types.

### Autosign

The recursive graph reaches V1/V5 vault services, bet service, Privy, HD wallet
derivation, Base RPC, pricing providers, GenLayer oracles, Solana RPC helpers,
KMS/env/hybrid signers and contract ABIs. These stay in FUDmarkets.

## Replacement boundary

| V1 behavior | Extracted replacement |
| --- | --- |
| Direct SQL user lookup | Send stable provider author ID; FUDmarkets resolves it |
| Bot-minted FUD JWT | HMAC-authenticated service request |
| Direct `autosignService` call | `/internal/agent/v1/actions` |
| Bot reads balances/markets from DB | Read-only backend API response or action receipt |
| Bot invokes vault/chain code | Canonical V2 engine inside FUDmarkets |
| In-memory provider update identity | Canonical `sourceEventId` plus durable backend receipt |

## Data model the backend must preserve

The social boundary depends on these canonical concepts, currently represented
by V1 PostgreSQL columns/tables:

- `users.telegram_id`, `users.telegram_username`;
- `users.x_user_id`, `users.x_username`;
- `tg_link_tokens(token, tg_id, user_id, expires_at)`;
- `x_oauth_tokens(oauth_token, oauth_token_secret, user_id, expires_at)`;
- `bot_kv(key, value)` for legacy poll/session state only;
- agent grant, nonce and idempotency receipt tables documented in the V2
  reference and OpenAPI contract.

The agent does not need this schema or a database connection. It needs stable
external IDs in its signed request and a typed result from FUDmarkets.

## What to copy versus what to rewrite

Preserve UX, command grammar, provider pagination/rate handling, identity
normalization, replies and error copy. Rewrite all direct imports listed above
against `FudEngineClient`. Do not copy monolith services into active `src/` just
to make the old files compile.
