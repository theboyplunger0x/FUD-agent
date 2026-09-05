# x-poster — Phase 1 (local validation)

Goal of this phase: confirm that Playwright + stealth can post a reply on X
on behalf of @FUDmarkets, using a saved logged-in session.

If this works locally, Phase 2 packages it as an Express service deployed
to Railway with a persistent volume.

## Setup

```bash
cd services/x-poster
npm install
npx playwright install chromium
```

## 1. Initial login (run once)

```bash
npm run x:login
```

A headed Chromium window opens at `x.com/i/flow/login`. Log in manually
with your @FUDmarkets credentials, complete 2FA / captcha if prompted,
wait until you see the home feed. Then return to the terminal and press
ENTER.

The script saves your session to `data/x-state.json`. This file is
gitignored — it contains your login cookies. **Treat it like a password.**

## 2. Test posting a reply

```bash
npm run x:post-test "https://x.com/somebody/status/123456789" "nice take, this aged well"
```

The script:

1. Loads the saved session into a fresh browser context
2. Navigates directly to the tweet URL
3. Clicks the reply box, types the text with realistic delays
4. Clicks the post button
5. Waits for confirmation, keeps browser open ~5s so you can see the result

Outcomes:

- **Success** → Playwright path is viable. Move to Phase 2 (Express server + Railway).
- **Selector mismatch** ("button not found") → X UI changed since this was written. Tell Claude what error you got, we adjust selectors.
- **Login redirect** → Session expired. Re-run `npm run x:login`.
- **Bot challenge / captcha mid-action** → X is suspicious. Try lower volume or add delays.

## What this doesn't do

- No anti-detect beyond `playwright-extra` + stealth plugin defaults
- No proxy
- No retry / queue / backpressure
- No HTTP API (that's Phase 2)
- No KOL tracker (that's Phase 4)

This is the smallest possible test that the bypass works at all.
