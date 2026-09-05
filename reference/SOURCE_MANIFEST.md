# Snapshot source manifest

- Original extraction base: FUDmarkets `4b578a01` on
  `codex/solana-agentic-session-keys`.
- V1 bot parity rechecked: FUDmarkets `origin/main`
  `73513082bc363d225b29f8f37bfaf0f38d55e448` on 2026-09-05.
- `reference/v1/fud-bot/{index,telegram,x,botGuards}.ts`,
  `reference/v1/routes/autosign.ts` and
  `reference/v1/services/autosignService.ts` were byte-identical to that main
  commit when rechecked.
- `reference/v1/routes/auth.ts` and `reference/v1/services/x-poster/` were copied
  from that main commit to complete the identity/posting handoff.
- `reference/v1/schema/social-agent.sql` is a curated, non-executable excerpt of
  the social tables/columns from FUDmarkets migrations at that commit.
- `reference/v2/` was synchronized against all current agent gateway, service
  auth, authorization, consent, grant, identity, signing and Solana provider
  source/tests at that main commit.

Reference code is deliberately excluded from the active build. When behavior in
FUDmarkets changes, update this manifest and explicitly decide whether the agent
contract or adapter must change; do not silently resnapshot production code.
