# FUD V2 Solana agentic execution plan

Status: active spike  
Branch: `codex/solana-agentic-session-keys`  
Started: 2026-09-03

## Objective

Preserve every useful FUD V1 bot flow on Solana without giving X, Telegram or
an AI agent arbitrary control of a user's wallet.

The supported product flow is:

```text
linked X / Telegram identity
  -> stable FUD user ID
  -> active, scoped and revocable authorization
  -> existing V2 risk and matching engine
  -> Solana aggregate collateral vault
```

## Architectural finding

The current Solana V2 vault mirrors the working Base V2 design:

- orders, matching, share pricing, user balances and positions live in Postgres;
- the Anchor program holds aggregate SPL-USDC collateral;
- only the configured FUD operator calls `open_market`, `mint_sets`,
  `burn_sets`, `resolve`, `settle` and `cancel_market`;
- the program does not currently receive one transaction or signature per user
  order.

Therefore MagicBlock Session Keys must **not** be added directly to the vault
as though each user placed an on-chain order. That would change the custody and
accounting model instead of merely migrating the chain.

For parity with V1, the first authorization boundary belongs between the social
bot and the V2 engine. A session must prove that the linked user authorized a
closed set of FUD actions. The existing operator then executes the already
validated aggregate chain leg.

MagicBlock remains a valuable phase-two option if FUD decides that the Solana
program itself must cryptographically enforce each user's scope, expiry and
spend caps.

## What has already been proven

On 2026-09-03 the deterministic suite in
`codex/magic-solana-autosign-poc` passed:

- local SPL delegation: 5/5 checks passed;
- FUD bot authorization policy: 15/15 tests passed;
- one authorization can cover both linked X and Telegram identities;
- wallet/user/program binding is enforced;
- per-order and session-total caps are enforced;
- expiry and revocation stop both channels immediately;
- nonce and source-event replay are rejected;
- Telegram value-moving callbacks require a private chat;
- withdrawals, arbitrary transfers and arbitrary program calls are absent from
  the delegated capability set.

This proves the policy model and a basic Solana delegate primitive. It does not
yet prove that Magic can create and sign with the production user's Solana
wallet, nor that the limits are enforced by the FUD Anchor program.

The production V2 seam now separately proves that the database is authoritative
for grant scope, revocation and cumulative use. The earlier bullets describe
the deterministic POC; they are not evidence of a live Magic integration.

## Required authorization scopes

### V1 parity

- `market.open_with_position`
- `market.take_pending`
- `market.bet_live`
- optional later: `market.cancel_pending`

### V2 order book

- `order.place`
- `order.cancel`
- optional later: `order.replace`
- optional later: `order.auto_reopen`
- optional later: `rewards.claim_to_balance`

Adding V2 must create a new grant. An old V1 grant must never gain order-book
permissions automatically.

### Never delegated

- withdrawals;
- arbitrary SOL/USDC/SPL transfers;
- arbitrary token approvals or SPL delegates;
- arbitrary program calls or message signing;
- wallet recovery or key export;
- creating or rotating another delegation;
- linking/unlinking X, Telegram, Discord, email or wallets;
- profile/security changes;
- market resolution, settlement, treasury or admin actions.

## Mandatory fields in a grant

```text
user_id
chain
wallet
session_delegate
target_program
environment / audience
allowed_channels[]
allowed_capabilities[]
allowed_market_ids[] or a constrained market rule
max_per_order_usdc
max_total_usdc
expires_at
revoked_at
```

`nonce`, `source_event_id` and `idempotency_key` belong to each signed action,
not to the immutable grant definition. All three are single-use per grant.

`max_total_usdc` means cumulative authorized turnover during one grant. It is a
conservative safety budget, not net settled outflow: fills, better execution,
cancellation and expiry do not replenish it. A user renews or rotates the grant
to receive a fresh budget. This intentionally prevents place/cancel churn from
recycling one delegation forever.

Market scope applies to both placement and cancellation. Exact retries return
the original durable receipt while a grant remains active; once revoked or
expired, even replay receipt access through that delegated channel fails closed.

The policy must mutate allowance, nonce and balance only after every validation
passes. A rejected action must leave all state untouched.

## Provider roles

| Component | Role | Current conclusion |
| --- | --- | --- |
| Magic | Login, embedded wallet and provider signing | Beta migration is being tested separately; live server-side Solana signing is still a release gate |
| MagicBlock | On-chain scoped session tokens | Best candidate for phase-two on-chain enforcement; not required for aggregate-vault parity |
| Para | Alternative MPC embedded wallet/signing provider | Keep as the fallback benchmark if Magic cannot satisfy stable offline signing |
| Solana Agent Kit | Agent tool adapter | Optional after authorization exists; never the security boundary |
| PNP/DFlow | Prediction-market references | Useful for comparison, not a replacement for FUD's matching engine |

## Execution plan

### Phase 1 — freeze the security contract

- [x] Inventory the X and Telegram actions reachable in V1.
- [x] Define allowed and forbidden capabilities.
- [x] Prove the deterministic policy model.
- [x] Prove SPL delegation, cap and revocation locally.
- [ ] Update V2 product timeframes and limits before freezing the signed schema.
- [x] Version the canonical grant and action payloads with separate
  `FUD_V2_AGENTIC_GRANT_V1` / `FUD_V2_AGENTIC_ACTION_V1` signing domains.

### Phase 2 — connect authorization to V2 without changing economics

- [x] Add a provider-neutral `AgenticAuthorizationProvider` interface.
- [x] Resolve social identity to the stable internal FUD user ID before parsing
  any value-moving action.
- [x] Persist grants, used nonces, used source events, cumulative spend and
  revocation transactionally.
- [x] Route authorized `order.place` and `order.cancel` through the existing V2
  guards/matching service, never through a parallel bot-only implementation.
- [x] Keep chain settlement on the existing operator-driven `ChainAdapter`.
- [x] Add one kill switch for agentic execution independent from normal web
  trading.

Implemented seam: `executeAgenticV2Action`. It resolves an immutable X or
Telegram identity, obtains the expected provider/wallet from an injected
trusted account binding, verifies both detached Ed25519 signatures, persists
the immutable grant, and calls the normal V2 executor. It is unreachable unless
`FUDV2_AGENTIC_ENABLED=true`; no public bot route is mounted yet.

The Solana verifier deliberately contains no Magic API call. Magic supplies the
embedded-wallet signature; FUD owns the canonical signed schema and verifies it
locally. This prevents a wallet vendor response from becoming the product
authorization policy.

Internal integration coverage now proves:

- linked X immutable id -> signed place -> real V2 resting order;
- an exact X retry returns the same durable order receipt;
- the same grant can cancel that order from the linked Telegram identity;
- Telegram value-moving actions reject outside a private chat;
- X cancellation rejects because V1 parity only exposes X opening/placement;
- an envelope signed by one wallet rejects when the trusted Magic account
  binding points to another wallet;
- per-order and cumulative session caps reject without consuming a nonce,
  source event, order or grant budget;
- an expired grant rejects without creating an order or consumption receipt;
- the strict signed schema rejects withdrawal, transfer and arbitrary-program
  capabilities before authorization;
- the independent kill switch fails before identity or provider work.

### Phase 3 — real Magic acceptance test

- [ ] Same Magic user returns the same Solana wallet.
- [ ] One explicit user authorization is created.
- [ ] Browser is closed.
- [ ] Linked X opens a market/position.
- [ ] Linked Telegram places and cancels an order.
- [ ] Per-order and total caps reject without state mutation.
- [ ] Expiry rejects.
- [ ] Revocation rejects both channels immediately.
- [ ] No bot route can withdraw or transfer to an arbitrary recipient.

The read-side binding adapter is now implemented as
`resolveMagicSolanaWalletBinding`. It fails closed unless the canonical user is
unbanned and has both a server-verified `magic_issuer` and a canonical
`solana_wallet_address`. The beta Magic migration and its Admin-SDK token
verification are now merged into the same integration branch.

The explicit browser consent ceremony is implemented: the backend prepares the
exact canonical grant, the Magic Solana wallet signs those bytes, and the
backend independently verifies the signature and every server-owned policy
field before activating it. Activation is transactional and leaves only one
active Magic grant per user, so repeated consent cannot multiply the total cap.

Before this phase can arm, one infrastructure piece still needs to land:

1. provision the agentic delegate KMS key and run the complete Phase 3 matrix
   against the deployed beta Magic wallet.

The code-side delegate signer is now implemented with an AWS KMS
`ECC_NIST_EDWARDS25519` signing key. Only its key id is configured through
`AGENTIC_DELEGATE_SOL_KMS_KEY_ID`; the private key is non-exportable. Every KMS
signature is verified locally before it is accepted into an envelope, and a
grant authorized for a different delegate key fails closed. Key rotation
changes the public key and therefore requires users to authorize fresh grants.

Do not store a session delegate private key in Postgres or a normal environment
variable. The remaining infrastructure step is to create a dedicated
`SIGN_VERIFY` KMS key, separate from treasury and V2 operator keys, and grant
the bot process only `kms:GetPublicKey` + `kms:Sign` on that key.

### Phase 4 — optional MagicBlock hardening

- [ ] Build a disposable-program spike first; do not modify the production vault.
- [ ] Compare native FUD authorization PDA vs MagicBlock Session Token.
- [ ] Enforce target program, instruction allowlist, expiry, spend cap and nonce
  on-chain.
- [ ] Test revoke, expired session, wrong instruction, wrong recipient, replay
  and cap overflow against a local validator.
- [ ] Adopt only if the extra on-chain guarantee justifies program complexity
  and audit surface.

### Phase 5 — provider decision

- [ ] Run the same acceptance matrix against Magic and Para.
- [ ] Compare stable wallet identity, offline signing, revocation latency,
  recovery, pricing, rate limits and export/migration path.
- [ ] Obtain legal review of the actual control model; do not infer
  non-custodial status from provider marketing.

## Release gates

No real funds until all of the following are green:

1. Solana V2 local-validator lifecycle and backend worker E2E.
2. Provider signing after browser close.
3. X and Telegram parity tests.
4. Transactional cap, nonce, replay and revoke enforcement.
5. Withdrawal and arbitrary-call negative tests.
6. Two RPC providers, monitoring and operator key controls.
7. Independent Anchor/security review.
8. Reconciled legacy Privy migration and rollback plan.

## Immediate next task

Merge the beta Magic auth migration, then implement the browser consent
ceremony that signs the exact V1 grant and run the Phase 3 acceptance matrix
against a real Magic Solana wallet. Grant state is already locked with `FOR
UPDATE`; DB revocation overrides stale envelopes; nonce, source event and
idempotency collisions fail closed; and the consumption receipt commits or
rolls back with `placeV2Order`/`cancelV2Order`. The focused agentic suite is
36/36 with a clean backend production build. Magic remains swappable because
no wallet-vendor code lives in the engine.

The identity resolver now accepts Telegram's immutable numeric id and X's
immutable provider user id. X usernames are deliberately rejected for
value-moving V2 actions because handles can be renamed or reassigned. Existing
verified raid links backfill `users.x_user_id`; other legacy X users must relink
once so the provider id can be captured.
