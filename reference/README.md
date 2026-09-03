# Reference snapshot

This directory is a read-only extraction snapshot from FUDmarkets commit
`4b578a01` on branch `codex/solana-agentic-session-keys`.

It includes:

- the complete V1 Telegram and X bot sources;
- V1 autosign service and route;
- V2 authorization, grant, consent, execution and Solana provider sources/tests;
- the existing bot and Solana-agentic planning documents.

These files intentionally retain imports from the monolith and are excluded from
the active TypeScript build. They are here to prevent feature loss and to make the
extraction reviewable. Migrate behavior adapter by adapter; do not make the
snapshot the production runtime and do not copy database/JWT access into `src/`.

