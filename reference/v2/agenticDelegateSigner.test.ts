import assert from "node:assert/strict";
import test from "node:test";
import { GetPublicKeyCommand, SignCommand } from "@aws-sdk/client-kms";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import {
  AwsKmsAgenticDelegateSigner,
  signSolanaAgenticIntent,
} from "./agenticDelegateSigner.js";
import {
  SolanaSessionAuthorizationProvider,
  solanaAgenticGrantBytes,
  type SolanaAgenticActionPayloadV1,
  type SolanaAgenticGrantDefinitionV1,
} from "./solanaAgenticProvider.js";

const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function fakeKms(keypair: Keypair, corruptSignature = false) {
  const calls: unknown[] = [];
  return {
    calls,
    async send(command: unknown) {
      calls.push(command);
      if (command instanceof GetPublicKeyCommand) {
        return { PublicKey: Uint8Array.from([...SPKI_PREFIX, ...keypair.publicKey.toBytes()]) };
      }
      if (command instanceof SignCommand) {
        const message = new Uint8Array(command.input.Message ?? []);
        const signature = nacl.sign.detached(message, keypair.secretKey);
        if (corruptSignature) signature[0] ^= 0xff;
        return { Signature: signature };
      }
      throw new Error("unexpected KMS command");
    },
  };
}

function fixture() {
  const wallet = Keypair.generate();
  const delegate = Keypair.generate();
  const marketId = "22222222-2222-4222-8222-222222222222";
  const grant: SolanaAgenticGrantDefinitionV1 = {
    version: 1,
    id: "grant-kms-1",
    provider: "magic",
    userId: "11111111-1111-4111-8111-111111111111",
    wallet: wallet.publicKey.toBase58(),
    chain: "solana",
    sessionDelegate: delegate.publicKey.toBase58(),
    targetProgram: Keypair.generate().publicKey.toBase58(),
    environment: "beta",
    audience: "fud-v2-order-engine",
    allowedChannels: ["x"],
    allowedCapabilities: ["order.place"],
    allowedMarketIds: [marketId],
    maxPerOrderUsdcBaseUnits: 10_000_000,
    maxTotalUsdcBaseUnits: 20_000_000,
    expiresAtSec: 1_900_000_000,
  };
  const intent: SolanaAgenticActionPayloadV1 = {
    version: 1,
    grantId: grant.id,
    userId: grant.userId,
    wallet: grant.wallet,
    channel: "x",
    externalIdentity: "x:123456",
    sourceEventId: "x:tweet:42",
    nonce: "1",
    action: {
      capability: "order.place",
      marketId,
      assetSide: "long",
      action: "buy",
      limitPriceCents: 55,
      sharesCenti: 1_000,
      tif: "gtc",
      expiresAtSec: null,
      idempotencyKey: "x:tweet:42",
    },
  };
  return { wallet, delegate, grant, intent };
}

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

test("KMS delegate signs an action and the production verifier accepts the envelope", async () => {
  const { wallet, delegate, grant, intent } = fixture();
  const kms = fakeKms(delegate);
  const signer = new AwsKmsAgenticDelegateSigner({
    keyId: "alias/fud-agentic-delegate",
    client: kms as never,
  });
  const grantSignature = Buffer.from(
    nacl.sign.detached(solanaAgenticGrantBytes(grant), wallet.secretKey),
  ).toString("base64");
  const envelope = await signSolanaAgenticIntent({ grant, grantSignature, intent, signer });
  const verified = await new SolanaSessionAuthorizationProvider().verify(envelope);
  assert.deepEqual(verified.action, intent.action);
  assert.equal(await signer.getPublicKey(), grant.sessionDelegate);
  assert.equal(kms.calls.filter((call) => call instanceof GetPublicKeyCommand).length, 1);
  assert.equal(kms.calls.filter((call) => call instanceof SignCommand).length, 1);
});

test("refuses a grant authorized for a different delegate", async () => {
  const { grant, intent } = fixture();
  const signer = new AwsKmsAgenticDelegateSigner({
    keyId: "alias/fud-agentic-delegate",
    client: fakeKms(Keypair.generate()) as never,
  });
  await expectCode("delegate_key_mismatch", () => signSolanaAgenticIntent({
    grant,
    grantSignature: "unused",
    intent,
    signer,
  }));
});

test("KMS signer fails closed if the returned signature does not verify", async () => {
  const delegate = Keypair.generate();
  const signer = new AwsKmsAgenticDelegateSigner({
    keyId: "alias/fud-agentic-delegate",
    client: fakeKms(delegate, true) as never,
  });
  await assert.rejects(() => signer.sign(new TextEncoder().encode("exact action")), /failed local verification/);
});

test("KMS signer rejects missing config and oversized messages", async () => {
  assert.throws(
    () => new AwsKmsAgenticDelegateSigner({ keyId: "", region: "" }),
    /AGENTIC_DELEGATE_SOL_KMS_KEY_ID/,
  );
  const delegate = Keypair.generate();
  const signer = new AwsKmsAgenticDelegateSigner({
    keyId: "alias/fud-agentic-delegate",
    client: fakeKms(delegate) as never,
  });
  await expectCode("bad_delegate_message", () => signer.sign(new Uint8Array(4_097)));
});
