# FUD V1 bots — historical behavior

This document is a concise index of the exact snapshots under `reference/v1/`.
For the authoritative provider/API split and target architecture, read
`../../docs/CHANNELS_AND_IDENTITY.md`.

## Processes

FUDmarkets V1 starts both social workers from its backend process:

```ts
startBot();
startXAgent();
```

They share PostgreSQL and directly call money-moving backend services. This is
historical context, not the architecture to reproduce.

## Telegram

The Telegraf bot supports token/CA search, interactive market creation, taking a
position, presets, account linking, group-to-DM handoff, profile/status commands
and the Telegram admin UX for X reply approval. It directly reads/writes users
and link tokens, mints a FUD JWT and calls autosign services.

## X

The X worker polls mentions and quotes through twitterapi.io, optionally drafts
responses with Anthropic, and routes drafts through Telegram approval. Mention
replies use the official X OAuth 1.0a posting API. Proactive replies use the
separate `x-poster` service when enabled. twitterapi.io session-login/posting
functions remain in the file but are not the active posting fallback.

## Identity

The saved `auth.ts` route shows user X OAuth linking and Telegram linking. Those
flows belong to FUDmarkets. A linked social account identifies a user but does
not itself grant trading authority.

## Migration rule

Retain provider UX and event semantics. Replace database access, JWT minting,
autosign imports and direct chain/vault calls with the signed agent API. See the
root extraction checklist for the remaining work.
