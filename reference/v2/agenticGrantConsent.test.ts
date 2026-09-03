import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import {
  agenticConsentPolicy,
  assertAgenticGrantMatchesConsent,
  prepareAgenticGrant,
} from "./agenticGrantConsent.js";
import {
  solanaAgenticGrantBytes,
  verifySolanaAgenticGrantSignature,
} from "./solanaAgenticProvider.js";

const NOW = 1_800_000_000;

function fixture() {
  const wallet = Keypair.generate();
  const delegate = Keypair.generate();
  const program = Keypair.generate();
  const policy = agenticConsentPolicy({
    V2_SOLANA_PROGRAM_ID: program.publicKey.toBase58(),
    FUDV2_AGENTIC_MAX_PER_ORDER_USDC_BASE_UNITS: "25000000",
    FUDV2_AGENTIC_MAX_TOTAL_USDC_BASE_UNITS: "100000000",
    FUDV2_AGENTIC_GRANT_TTL_SECONDS: "3600",
  }, "beta");
  const grant = prepareAgenticGrant({
    userId: "11111111-1111-4111-8111-111111111111",
    wallet: wallet.publicKey.toBase58(),
    sessionDelegate: delegate.publicKey.toBase58(),
    policy,
    nowSec: NOW,
    id: "22222222-2222-4222-8222-222222222222",
  });
  return { wallet, delegate, policy, grant };
}

async function expectCode(code: string, operation: () => unknown): Promise<void> {
  await assert.rejects(async () => operation(), (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

test("Magic wallet signs the exact server-prepared Solana grant", () => {
  const { wallet, delegate, policy, grant } = fixture();
  const signature = nacl.sign.detached(solanaAgenticGrantBytes(grant), wallet.secretKey);
  const verified = verifySolanaAgenticGrantSignature(grant, Buffer.from(signature).toString("base64"));
  assert.deepEqual(verified, grant);
  assert.doesNotThrow(() => assertAgenticGrantMatchesConsent({
    grant: verified,
    userId: grant.userId,
    wallet: wallet.publicKey.toBase58(),
    sessionDelegate: delegate.publicKey.toBase58(),
    policy,
    nowSec: NOW,
  }));
});

test("consent rejects widened scope, changed identity, delegate and expiry", async () => {
  const { wallet, delegate, policy, grant } = fixture();
  const base = {
    userId: grant.userId,
    wallet: wallet.publicKey.toBase58(),
    sessionDelegate: delegate.publicKey.toBase58(),
    policy,
    nowSec: NOW,
  };
  for (const changed of [
    { ...grant, maxTotalUsdcBaseUnits: grant.maxTotalUsdcBaseUnits + 1 },
    { ...grant, wallet: Keypair.generate().publicKey.toBase58() },
    { ...grant, sessionDelegate: Keypair.generate().publicKey.toBase58() },
    { ...grant, allowedMarketIds: ["market-any"] },
  ]) {
    await expectCode("grant_policy_mismatch", () => assertAgenticGrantMatchesConsent({
      ...base,
      grant: changed,
    }));
  }
  await expectCode("grant_expiry_out_of_policy", () => assertAgenticGrantMatchesConsent({
    ...base,
    grant: { ...grant, expiresAtSec: NOW + policy.ttlSeconds + 1 },
  }));
});

test("consent policy fails closed on invalid runtime limits and program", () => {
  assert.throws(() => agenticConsentPolicy({ V2_SOLANA_PROGRAM_ID: "bad" }, "beta"));
  assert.throws(() => agenticConsentPolicy({
    V2_SOLANA_PROGRAM_ID: Keypair.generate().publicKey.toBase58(),
    FUDV2_AGENTIC_MAX_PER_ORDER_USDC_BASE_UNITS: "200",
    FUDV2_AGENTIC_MAX_TOTAL_USDC_BASE_UNITS: "100",
  }, "beta"), /cannot exceed/);
});
