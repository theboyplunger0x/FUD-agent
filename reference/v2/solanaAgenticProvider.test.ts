import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { AgenticAuthorizationError, type AgenticPlaceOrder } from "./agenticAuthorization.js";
import {
  SolanaSessionAuthorizationProvider,
  solanaAgenticActionBytes,
  solanaAgenticGrantBytes,
  type SolanaAgenticActionPayloadV1,
  type SolanaAgenticEnvelopeV1,
  type SolanaAgenticGrantDefinitionV1,
} from "./solanaAgenticProvider.js";

const USER = "11111111-1111-4111-8111-111111111111";
const MARKET = "22222222-2222-4222-8222-222222222222";

function signedEnvelope(input: {
  wallet?: Keypair;
  delegate?: Keypair;
  grant?: Partial<SolanaAgenticGrantDefinitionV1>;
  intent?: Partial<SolanaAgenticActionPayloadV1>;
  action?: Partial<AgenticPlaceOrder>;
} = {}): SolanaAgenticEnvelopeV1 {
  const wallet = input.wallet ?? Keypair.generate();
  const delegate = input.delegate ?? Keypair.generate();
  const program = Keypair.generate().publicKey.toBase58();
  const grant: SolanaAgenticGrantDefinitionV1 = {
    version: 1,
    id: "grant-1",
    provider: "magic",
    userId: USER,
    wallet: wallet.publicKey.toBase58(),
    chain: "solana",
    sessionDelegate: delegate.publicKey.toBase58(),
    targetProgram: program,
    environment: "beta",
    audience: "fud-v2-order-engine",
    allowedChannels: ["x", "telegram"],
    allowedCapabilities: ["order.place", "order.cancel"],
    allowedMarketIds: [MARKET],
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 25_000_000,
    expiresAtSec: 1_900_000_000,
    ...input.grant,
  };
  const action: AgenticPlaceOrder = {
    capability: "order.place",
    marketId: MARKET,
    assetSide: "long",
    action: "buy",
    limitPriceCents: 55,
    sharesCenti: 1_000,
    tif: "gtc",
    expiresAtSec: null,
    idempotencyKey: "x:tweet:123",
    ...input.action,
  };
  const intent: SolanaAgenticActionPayloadV1 = {
    version: 1,
    grantId: grant.id,
    userId: grant.userId,
    wallet: grant.wallet,
    channel: "x",
    externalIdentity: "x:123456",
    sourceEventId: "x:tweet:123",
    nonce: "1",
    action,
    ...input.intent,
  };
  return {
    version: 1,
    grant,
    grantSignature: Buffer.from(
      nacl.sign.detached(solanaAgenticGrantBytes(grant), wallet.secretKey),
    ).toString("base64"),
    intent,
    intentSignature: Buffer.from(
      nacl.sign.detached(solanaAgenticActionBytes(intent), delegate.secretKey),
    ).toString("base64"),
  };
}

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

test("verifies the user grant and exact delegate action", async () => {
  const envelope = signedEnvelope();
  const verified = await new SolanaSessionAuthorizationProvider().verify(envelope);
  assert.equal(verified.userId, USER);
  assert.equal(verified.wallet, envelope.grant.wallet);
  assert.equal(verified.grant.spentUsdcBaseUnits, 0);
  assert.equal(verified.grant.revokedAtSec, null);
  assert.deepEqual(verified.action, envelope.intent.action);
});

test("rejects a grant changed after the user signature", async () => {
  const envelope = signedEnvelope();
  envelope.grant.maxTotalUsdcBaseUnits += 1;
  await expectCode(
    "invalid_grant_signature",
    () => new SolanaSessionAuthorizationProvider().verify(envelope),
  );
});

test("rejects an action changed after the delegate signature", async () => {
  const envelope = signedEnvelope();
  if (envelope.intent.action.capability !== "order.place") throw new Error("bad fixture");
  envelope.intent.action.sharesCenti += 1;
  await expectCode(
    "invalid_intent_signature",
    () => new SolanaSessionAuthorizationProvider().verify(envelope),
  );
});

test("rejects signatures from the wrong wallet and delegate", async () => {
  const walletEnvelope = signedEnvelope();
  walletEnvelope.grantSignature = Buffer.from(
    nacl.sign.detached(solanaAgenticGrantBytes(walletEnvelope.grant), Keypair.generate().secretKey),
  ).toString("base64");
  await expectCode(
    "invalid_grant_signature",
    () => new SolanaSessionAuthorizationProvider().verify(walletEnvelope),
  );

  const delegateEnvelope = signedEnvelope();
  delegateEnvelope.intentSignature = Buffer.from(
    nacl.sign.detached(solanaAgenticActionBytes(delegateEnvelope.intent), Keypair.generate().secretKey),
  ).toString("base64");
  await expectCode(
    "invalid_intent_signature",
    () => new SolanaSessionAuthorizationProvider().verify(delegateEnvelope),
  );
});

test("binds the signed action to one grant, user and wallet", async () => {
  for (const change of [
    { grantId: "other-grant" },
    { userId: "other-user" },
    { wallet: Keypair.generate().publicKey.toBase58() },
  ]) {
    const envelope = signedEnvelope({ intent: change });
    await expectCode(
      "signed_grant_intent_mismatch",
      () => new SolanaSessionAuthorizationProvider().verify(envelope),
    );
  }
});

test("domain separation prevents reusing a grant signature as an action signature", async () => {
  const signer = Keypair.generate();
  const envelope = signedEnvelope({ wallet: signer, delegate: signer });
  envelope.intentSignature = envelope.grantSignature;
  await expectCode(
    "invalid_intent_signature",
    () => new SolanaSessionAuthorizationProvider().verify(envelope),
  );
});

test("rejects malformed, extra and non-canonical fields before normalization", async () => {
  const extra = signedEnvelope() as SolanaAgenticEnvelopeV1 & { admin?: boolean };
  extra.admin = true;
  await expectCode("bad_signed_envelope", () => (
    new SolanaSessionAuthorizationProvider().verify(extra)
  ));

  const badWallet = signedEnvelope();
  badWallet.grant.wallet = "not-a-solana-key";
  await expectCode("bad_grant_wallet", () => (
    new SolanaSessionAuthorizationProvider().verify(badWallet)
  ));

  const duplicateScope = signedEnvelope();
  duplicateScope.grant.allowedChannels = ["x", "x"];
  await expectCode("bad_signed_grant", () => (
    new SolanaSessionAuthorizationProvider().verify(duplicateScope)
  ));

  const badSignature = signedEnvelope();
  badSignature.intentSignature = "%%%";
  await expectCode("bad_intent_signature", () => (
    new SolanaSessionAuthorizationProvider().verify(badSignature)
  ));
});

test("signed envelopes cannot introduce withdrawal, transfer or arbitrary calls", async () => {
  for (const capability of ["wallet.withdraw", "wallet.transfer", "program.call"]) {
    const envelope = signedEnvelope();
    envelope.intent.action = {
      capability,
      marketId: envelope.grant.allowedMarketIds?.[0] ?? "market",
      recipient: Keypair.generate().publicKey.toBase58(),
      amount: 1,
      idempotencyKey: `forbidden:${capability}`,
    } as never;
    await expectCode("bad_signed_action", () => (
      new SolanaSessionAuthorizationProvider().verify(envelope)
    ));
  }
});
