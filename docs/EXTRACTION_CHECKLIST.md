# Extraction checklist

## 1. Establish the backend seam

- [x] Define the versioned action contract.
- [x] Add agent-side HMAC signing.
- [x] Add HMAC verification and one-time nonce storage to FUDmarkets.
- [x] Mount `POST /internal/agent/v1/actions` in FUDmarkets.
- [x] Resolve the external identity only in FUDmarkets.
- [x] Check grant, capability, expiry and caps before every execution.
- [x] Store a durable idempotency receipt keyed by channel + source event ID.
- [x] Return the original receipt for exact retries and reject collisions.
- [ ] Add cross-repository contract tests.

## 2. Complete the V2 capabilities

- [x] Preserve current `order.place` and `order.cancel` agentic execution code.
- [ ] Implement `market.open_with_position` through the canonical V2 engine.
- [ ] Make market creation and initial position one idempotent workflow.
- [ ] Define failure/refund semantics if chain creation succeeds partially.
- [ ] Confirm 6h/12h/24h are enforced by the backend, not only the bot.
- [ ] Keep withdrawals outside the initial capability set.

## 3. Extract Telegram

- [x] Preserve the full V1 Telegram source in `reference/v1/fud-bot`.
- [ ] Move Telegram command and callback UX into an active adapter.
- [ ] Verify Telegram webhook secret before accepting events.
- [ ] Require private chat for money-moving actions.
- [ ] Replace direct PostgreSQL/JWT/service imports with `FudEngineClient`.
- [ ] Preserve link, unlink, status, cancel and user-facing error flows.
- [ ] Add provider fixture tests and duplicate-delivery tests.

## 4. Extract X

- [x] Preserve the full V1 X source in `reference/v1/fud-bot`.
- [ ] Move polling/webhook ingestion and reply UX into an active adapter.
- [ ] Verify/canonicalize author ID, tweet ID and conversation context.
- [ ] Replace direct PostgreSQL/JWT/service imports with `FudEngineClient`.
- [ ] Separate optional LLM interpretation from execution authorization.
- [ ] Add rate-limit, pagination, restart and duplicate-delivery tests.

## 5. Delegate signing and consent

- [x] Preserve V2 authorization, consent, grant store and Solana provider code.
- [ ] Choose the production Solana embedded-wallet/delegation provider.
- [x] Keep delegate signing in FUDmarkets behind the AWS KMS implementation.
- [x] Bind every signed action to the active user grant and exact payload.
- [ ] Exercise revoke, expiry, per-action cap and daily-cap end-to-end tests.
- [ ] Confirm legal/product wording for agent authorization.

## 6. Operations and cutover

- [ ] Add structured audit events without tokens or wallet secrets.
- [ ] Add alerts for provider failure, replay rejection and execution drift.
- [ ] Run shadow mode: parse and authorize without submitting transactions.
- [ ] Canary one channel and a small allowlist of users.
- [ ] Compare receipts against V1 behavior before enabling value movement.
- [ ] Disable V1 bot workers only after the canary and rollback test pass.
