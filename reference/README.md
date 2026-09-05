# Reference snapshot

This directory is a read-only extraction snapshot. It began at FUDmarkets commit
`4b578a01` on branch `codex/solana-agentic-session-keys`; V1 bot parity was
rechecked against `origin/main` commit `73513082` on 2026-09-05. See
`SOURCE_MANIFEST.md` for provenance.

It includes:

- the complete V1 Telegram and X bot sources;
- the complete V1 auth route containing X/Telegram account linking;
- the complete `x-poster` browser-session reply service;
- a reference-only excerpt of the social identity schema;
- V1 autosign service and route;
- the current V2 gateway, service authentication, authorization, grant,
  consent, execution and Solana provider sources/tests;
- the existing bot and Solana-agentic planning documents.

These files intentionally retain imports from the monolith and are excluded from
the active TypeScript build. They are here to prevent feature loss and to make the
extraction reviewable. Migrate behavior adapter by adapter; do not make the
snapshot the production runtime and do not copy database/JWT access into `src/`.
