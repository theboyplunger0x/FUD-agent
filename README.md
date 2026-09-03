# FUD Agent

Isolated social-agent gateway for FUD Markets. It receives authenticated events
from Telegram or X, converts them into a small set of deterministic intents and
sends those intents to the canonical FUDmarkets backend through a signed internal
API.

This repository does **not** own balances, user wallets, market state, matching,
settlement or treasury keys. Those remain in FUDmarkets.

## Why this repository exists

The V1 bots live inside the main backend and can access PostgreSQL, mint user JWTs
and call money-moving services directly. That makes the bot process too powerful
and makes a Solana migration unnecessarily risky. This repository creates a hard
boundary:

```text
Telegram / X
      |
      v
provider verification + command parsing       (this repository)
      |
      v  HMAC-signed request + source event id
FUDmarkets internal agent API                  (main repository)
      |
      +-- linked identity
      +-- explicit user grant / autosign policy
      +-- amount and time caps
      +-- replay protection
      +-- balances + V2 engine + chain execution
```

An LLM may help interpret natural language in a future adapter, but it must never
directly create a value-moving request. Every action must pass through a strict
intent parser and the authorization checks in FUDmarkets.

## Current status

- The isolated gateway, strict parser, HMAC request signing and API contract are
  implemented and tested.
- The current Telegram, X, V1 autosign and V2 Solana agentic code is preserved in
  `reference/` as an extraction snapshot from FUDmarkets commit `4b578a01`.
- The FUDmarkets endpoint `/internal/agent/v1/actions` is specified but is not yet
  mounted in the main backend.
- Current V2 agentic execution supports `order.place` and `order.cancel`.
  `market.open_with_position` still needs its canonical backend implementation.
- Provider-specific Telegram and X adapters still need to be migrated out of the
  snapshot and wired to the gateway.

Therefore this is a safe, independently buildable extraction foundation—not yet
a production replacement for the V1 bots.

## Supported intents

```text
open $BONK 6h long $25 optional thesis
buy <market-id> short $10 max 42c
cancel <market-id> <order-id>
```

Markets are Solana-only and use the product timeframes `6h`, `12h` and `24h`.

## Local development

Requirements: Node.js 20 or newer.

```bash
cp .env.example .env
npm install
npm run check
npm run dev
```

The service exposes `GET /health`. `POST /events` is an internal normalized-event
route for development; do not expose it publicly until the Telegram/X ingress
adapters verify provider authenticity.

## Repository map

- `src/domain.ts`: channel event schema and deterministic intent parser.
- `src/request-signing.ts`: versioned HMAC service authentication.
- `src/engine-client.ts`: the only active connection to FUDmarkets.
- `src/gateway.ts`: validation → parsing → engine request.
- `contracts/fud-agent-engine.openapi.yaml`: cross-repository API contract.
- `docs/SECURITY_BOUNDARY.md`: ownership and trust rules.
- `docs/EXTRACTION_CHECKLIST.md`: executable migration sequence.
- `reference/`: read-only snapshot of the existing implementation.

## Secret policy

Never add `DATABASE_URL`, `JWT_SECRET`, a treasury key, a user-wallet key, the V2
operator key or a raw Magic secret to this repository. The agent gets only channel
credentials, a dedicated service HMAC secret and—when enabled—a narrowly scoped
delegate KMS key.

