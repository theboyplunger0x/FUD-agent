# FUD Agent

> Turn authenticated Telegram and X activity into safe, permissioned actions on
> the FUD Markets V2 engine.

FUD Agent is the isolated social gateway for FUD Markets. It receives events
from Telegram or X, verifies and normalizes them, converts commands into a small
set of deterministic intents and sends a signed request to the canonical
FUDmarkets backend.

The repository contains both the new gateway and the full historical context
needed to migrate the V1 bots without losing behavior.

## The idea

```text
Telegram / X
      │
      ▼
provider verification + UX + deterministic parsing       FUD Agent
      │
      ▼  HMAC request + immutable source event ID
identity + grant + limits + replay protection             FUDmarkets
      │
      ▼
balances + matching + settlement + Solana V2 engine       Canonical backend
```

The agent may understand what a user wants, but it never gets unilateral access
to their funds. FUDmarkets resolves the linked identity and revalidates consent,
capabilities, expiry, per-action limits, daily limits and idempotency before any
execution.

## Why it is separate

The original V1 Telegram and X workers run inside the main backend. They can
query PostgreSQL, mint user JWTs and call autosign, vault and chain services
directly. That worked, but it gives a social bot far more power than it needs.

This extraction creates a strict boundary:

- FUD Agent owns provider credentials, provider verification, channel UX,
  parsing and signed service requests.
- FUDmarkets owns identities, wallets, Magic grants, balances, trading,
  settlement, KMS signing and the audit trail.
- An LLM can suggest an interpretation or draft a reply; its output must still
  pass the typed parser and backend authorization.

## Current state

| Area | Status |
| --- | --- |
| Isolated Fastify gateway | Ready and tested |
| Deterministic command parser | Ready and tested |
| HMAC service authentication | Ready and tested |
| Cross-repository OpenAPI contract | Ready |
| FUDmarkets `/internal/agent/v1/actions` seam | Present on FUDmarkets `main` |
| V2 `order.place` and `order.cancel` | Implemented in the backend seam |
| V2 `market.open_with_position` | Contract defined; canonical execution pending |
| Telegram provider adapter | Full V1 behavior preserved; active extraction pending |
| X provider adapter | Full V1 behavior preserved; active extraction pending |
| Production cutover | Not armed |

This is a safe, independently buildable migration foundation. It is not yet the
production replacement for the V1 workers.

## Supported command grammar

```text
open $BONK 6h long $25 optional thesis
buy <market-id> short $10 max 42c
cancel <market-id> <order-id>
```

The new product path is Solana-only and accepts `6h`, `12h` and `24h` markets.
Deprecated V1 timeframes are rejected by the parser.

## X and Telegram coverage

The handoff includes the complete integration map, not only the command parser:

- twitterapi.io reads mentions, tweets, recent posts and quote tweets;
- the official X API posts replies from `@FUDmarkets` using OAuth 1.0a;
- the separate `x-poster` service is preserved as the optional proactive-post
  browser-session fallback;
- the official OAuth flow that links an X account to a FUD user is preserved;
- Telegram linking, commands, inline keyboards, market flow, presets and the X
  reply-approval workflow are preserved;
- the relevant identity schema and every environment-variable name are mapped.

See [Channels and identity](docs/CHANNELS_AND_IDENTITY.md) for the exact API and
credential split.

## Run locally

Requires Node.js 20 or newer.

```bash
git clone https://github.com/theboyplunger0x/FUD-agent.git
cd FUD-agent
cp .env.example .env
npm install
npm run check
npm run dev
```

The service exposes:

- `GET /health` — local health check;
- `POST /events` — normalized development ingress.

Do not expose `/events` publicly until the active Telegram/X adapters perform
provider-specific authenticity verification.

## Repository guide

```text
src/
  domain.ts             normalized events + strict intent parser
  request-signing.ts    versioned HMAC signing and verification
  engine-client.ts      the only active connection to FUDmarkets
  gateway.ts            event -> intent -> signed engine request
  server.ts             Fastify entrypoint

contracts/
  fud-agent-engine.openapi.yaml

docs/
  CHANNELS_AND_IDENTITY.md    exact X/Telegram flows and API ownership
  ENVIRONMENT_CONTRACT.md     variables and secret ownership by service
  MONOLITH_DEPENDENCIES.md    what V1 imports and how to replace it
  SECURITY_BOUNDARY.md        non-negotiable trust rules
  EXTRACTION_CHECKLIST.md     executable migration/cutover checklist

reference/
  v1/                    exact V1 bots, auth, autosign and x-poster context
  v2/                    current gateway, grants, Magic and Solana sources/tests
  SOURCE_MANIFEST.md     snapshot provenance and synchronization point
```

Files under `reference/` are deliberately excluded from the active TypeScript
build. They are migration evidence, not code to deploy unchanged.

## Recommended next work

1. Extract the Telegram adapter and preserve its existing UX while replacing
   direct SQL/JWT/autosign access with `FudEngineClient`.
2. Extract X ingestion and posting, keeping twitterapi.io reads, official API
   replies and `x-poster` fallback as explicit separate components.
3. Add provider fixtures, duplicate-delivery, pagination, restart and rate-limit
   tests.
4. Implement atomic `market.open_with_position` in the canonical V2 engine,
   including partial-failure and refund semantics.
5. Run shadow mode, then a restricted canary, before disabling V1 workers.

The detailed order and acceptance criteria live in
[the extraction checklist](docs/EXTRACTION_CHECKLIST.md).

## Security rules

Never add any of the following to this repository:

- `DATABASE_URL` or production database credentials;
- `JWT_SECRET`;
- a Magic secret/admin key;
- user-wallet, treasury, operator or delegate private keys;
- AWS KMS signing access;
- Playwright/X session cookies.

FUD Agent receives only channel credentials and a dedicated service HMAC
secret. Wallet/grant verification and all value-moving execution stay inside
FUDmarkets. See [Security boundary](docs/SECURITY_BOUNDARY.md) and
[Environment contract](docs/ENVIRONMENT_CONTRACT.md).

## Verification

```bash
npm run typecheck
npm test
npm run check
```

The current suite covers intent parsing, allowed Solana timeframes, Telegram DM
enforcement, request normalization, HMAC verification, tampering and stale
requests.

---

Built as the social execution boundary for the next version of FUD Markets.
