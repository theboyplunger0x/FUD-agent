# Bot autosign — E2E runbook + release-day checklist

> Status (2026-05-12): backend + bot wiring + UI committed. UI hidden
> behind `SHOW_AUTOSIGN = false`. Backend gated by `AUTOSIGN_ENABLED`.
> Run this runbook on testnet to validate before flipping to public.

## TL;DR

1. **Setup once**: Privy creds in Railway, run spike, deploy backend.
2. **Run 7 scenarios** in this doc against testnet. Use `autosignE2EVerify.ts` after each.
3. **Smoke pass** → flip `SHOW_AUTOSIGN = true` + `vercel --prod`.
4. **Rollback** = flag flip + redeploy (frontend) or `AUTOSIGN_ENABLED=0` + railway up (backend).

---

## Setup (one-time, ~15 min)

### Privy dashboard
- [ ] **Wallet infrastructure > Authorization keys** → "Create new key"
- [ ] Copy the resulting `PRIVY_APP_SECRET`

### Railway backend env
```bash
# Set in Railway dashboard or via CLI:
railway variables --set "PRIVY_APP_SECRET=<from above>" \
                  --set "AUTOSIGN_ENABLED=1"
```

### Run the Privy spike (binary go/no-go)
```bash
# Pre-req: in browser as a test user, open console:
#   const { delegateWallet } = window.__privy?.delegated ?? {};
#   await delegateWallet({ address: '<embedded>', chainType: 'ethereum' });
# Then copy that user's did:privy:cm... from Privy dashboard.

cd backend
export PRIVY_APP_SECRET=<from above>
export PRIVY_TEST_USER_DID=did:privy:cm...
export FUDVAULT_ADDRESS=<from backend.env>
npx tsx scripts/privyAutosignSpike.ts
```
- **Exit 0** = Path A works. Proceed.
- **Non-zero** = Path A failed. STOP and review output. Do not deploy.

### Deploy backend with autosign enabled
```bash
cd /Users/lanzanimarcos7/Desktop/Proyectos/FUDmarkets/backend
railway up --service "FUD. backend" -e production
```
- Migration applies on startup (`bot_autosign_consents` table)
- Verify: `curl https://<backend-url>/autosign/status` with a valid JWT → `runtime_ready: true`

### Pre-flight verify
```bash
cd backend
npx tsx scripts/autosignE2EVerify.ts pre
```
Must print all ✅.

---

## Test environment

- **Chain**: Base Sepolia
- **Frontend**: `https://fud-markets.vercel.app` (UI still hidden — use direct API or temporarily flip flag locally)
- **Bots**: Telegram + X running on production Railway
- **DB**: production = testnet
- **Users**:
  - User A: linked Telegram + Privy embedded wallet + ~$200 USDC in FUDVault
  - User B: linked X + Privy embedded wallet + ~$200 USDC in FUDVault
  - User C: linked Telegram + Privy wallet + $0 in FUDVault (for balance test)

---

## Scenarios

For each scenario, after the action, run:
```bash
cd backend
npx tsx scripts/autosignE2EVerify.ts <id> <user_id>
```

### S1 — Web: Enable autosign

**Pre-req**: temporarily flip `SHOW_AUTOSIGN = true` in local dev to access the UI, OR call `POST /autosign/consent` directly.

**Action**: Settings → 🤖 Bot autosign → Enable → Privy consent prompt → accept.

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s1 <user_a_id>
```
Expected: ✅ Consent active with wallet_id stored.

---

### S2 — Telegram: autosign happy path

**Pre-req**: S1 passed for User A.

**Action**: From Telegram (User A):
```
/start  (confirm session)
/trade $PEPE   (or whatever token search command)
→ pick 1h → pick long → pick $50 → Confirm
```

**Expected bot reply**: `📈 LONG $50 on $PEPE · 1h — done ✅` (no link).

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s2-ok <user_a_id>
```
Expected: ✅ Position landed with onchain_tx.

---

### S3 — Telegram: no autosign → fallback

**Pre-req**: User B has NEVER enabled autosign (no consent row).

**Action**: Same flow as S2 from User B's Telegram.

**Expected bot reply**: standard `🔥 Confirm trade on FUD.markets →` link.

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s3-fb <user_b_id>
```
Expected: ✅ No position landed yet — fallback to link.

---

### S4 — Telegram: terminal rejection (over MAX_SINGLE_BET)

**Pre-req**: User A has autosign active and enough balance.

**Action**: Same flow but pick $1000 (over default `MAX_SINGLE_BET=$500`).

**Expected bot reply**: `❌ Bet exceeds maximum of $500 per trade` (NO link).

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s4-cap <user_a_id>
```
Expected: ✅ No position landed.

**Also check** (group chat behavior — Codex P1 fix):
- If trade was in a group chat: NO challenge card should be posted to group.

---

### S5 — Telegram: insufficient balance

**Pre-req**: User C with $0 in vault, autosign active.

**Action**: Try to trade $50.

**Expected bot reply**: Should be caught BEFORE autosign — `💸 Not enough USDC in your vault` from the existing balance gate. If somehow it reaches autosign: `❌ Not enough USDC in your vault`.

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s5-bal <user_c_id>
```
Expected: ✅ No position.

---

### S6 — X: autosign happy path

**Pre-req**: User B enabled autosign (S1 done for B), has balance.

**Action**: Tweet `@FUDmarkets short $50 $WIF 1h`.

**Expected bot reply**: `Done. short $50 $WIF 1h opened ✅` + link as follow-up.

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s2-ok <user_b_id>
```
Expected: ✅ Position landed.

---

### S7 — Revoke

**Pre-req**: User A still has active consent.

**Action**: Settings → Revoke (or `DELETE /autosign/consent` directly).

**Verify**:
```bash
npx tsx scripts/autosignE2EVerify.ts s9-revoked <user_a_id>
```
Expected: ✅ revoked_at set.

**Then**: trigger another bot trade from User A — bot should fall back to web link (NOT autosign).

---

## Pass criteria for launch

All 7 scenarios green. Specifically:

- **S2 + S6**: autosign actually executes (the core product promise)
- **S4**: terminal rejection shown directly, no dead-end link, no group challenge card
- **S5**: balance gate fires before signing waste
- **S7**: revoke is immediate, autosign stops next attempt

If any of these fail: do NOT proceed to UI flip.

---

## Release day (after E2E passes)

1. **Frontend**: edit [src/account/AccountDrawer.tsx](../src/account/AccountDrawer.tsx) → `SHOW_AUTOSIGN = true`
2. ```bash
   cd /Users/lanzanimarcos7/Desktop/Proyectos/FUDmarkets && vercel --prod
   ```
3. **Smoke test in prod** with a low-stakes test account (~$5 USDC).
4. Announce 🎉

---

## Rollback

**Hide UI** (kills new opt-ins, doesn't affect existing consents):
- `SHOW_AUTOSIGN = false` → `vercel --prod`

**Kill autosign entirely** (bots fall back to web link for everyone):
- Railway: `AUTOSIGN_ENABLED=0` → `railway up`

**Revoke a specific user**:
```sql
UPDATE bot_autosign_consents SET revoked_at = NOW() WHERE user_id = '...';
```
