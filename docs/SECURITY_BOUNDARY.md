# Security boundary

## This repository owns

- Telegram and X webhook/poller authenticity verification.
- Channel-specific UX and replies.
- Normalization of external identities and immutable source-event IDs.
- Strict parsing into an allowlisted action schema.
- A dedicated delegate signer only when a user grant explicitly permits it.
- Signed service-to-service requests and operational telemetry.

## FUDmarkets owns

- Mapping X/Telegram identities to the authenticated FUD user and wallet.
- Grant creation, revocation, expiry, capabilities and per-action/daily caps.
- Replay protection and durable idempotency receipts.
- Balances, reservations, matching, fees and market state.
- Market creation, chain submission, settlement and withdrawals.
- Treasury, wallet custody material and the canonical audit trail.

## Non-negotiable rules

1. A social identity is not sufficient authorization to move funds.
2. Every value-moving event needs an active, server-verified user grant.
3. Telegram value-moving commands require a private chat.
4. Every provider event receives a canonical, durable source-event ID.
5. Duplicate retries return the original receipt; conflicting reuse is rejected.
6. FUDmarkets revalidates amounts, prices, market state and available balance.
7. Natural-language or LLM output never bypasses the typed intent parser.
8. The agent cannot mint user sessions or query the production database.
9. Delegate keys are scoped, rotatable and separate from operator/treasury keys.
10. Withdrawal is not an agent capability unless separately designed and approved.

## Signed request

The current contract signs:

```text
FUD_AGENT_REQUEST_V1
<HTTP METHOD>
<PATH>
<UNIX TIMESTAMP>
<UUID NONCE>
<SHA256 BODY>
```

FUDmarkets must enforce a short timestamp window, consume each nonce once and
compare signatures in constant time. The source event ID is a second, durable
idempotency layer because a new request nonce can still retry the same provider
event.

