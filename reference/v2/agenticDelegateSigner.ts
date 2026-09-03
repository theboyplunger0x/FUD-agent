import { GetPublicKeyCommand, KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import { spkiToEd25519PublicKey } from "../services/signer/awsKmsSigner.js";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import {
  solanaAgenticActionBytes,
  type SolanaAgenticActionPayloadV1,
  type SolanaAgenticEnvelopeV1,
  type SolanaAgenticGrantDefinitionV1,
} from "./solanaAgenticProvider.js";

export interface AgenticDelegateSigner {
  getPublicKey(): Promise<string>;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export type AwsKmsAgenticDelegateSignerConfig = {
  keyId?: string;
  region?: string;
  client?: Pick<KMSClient, "send">;
};

/**
 * One non-exportable Ed25519 KMS key may be authorized by many user grants.
 * Its compromise radius is still bounded by each grant's scope/caps/expiry.
 * Rotation changes the delegate pubkey and therefore requires fresh grants.
 */
export class AwsKmsAgenticDelegateSigner implements AgenticDelegateSigner {
  private readonly keyId: string;
  private readonly client: Pick<KMSClient, "send">;
  private cachedPublicKey: PublicKey | null = null;

  constructor(config: AwsKmsAgenticDelegateSignerConfig = {}) {
    this.keyId = config.keyId?.trim()
      || process.env.AGENTIC_DELEGATE_SOL_KMS_KEY_ID?.trim()
      || "";
    if (!this.keyId) {
      throw new Error("AGENTIC_DELEGATE_SOL_KMS_KEY_ID is required");
    }
    const region = config.region?.trim()
      || process.env.AWS_REGION?.trim()
      || process.env.KMS_AWS_REGION?.trim()
      || "";
    if (!config.client && !region) {
      throw new Error("AWS_REGION (or KMS_AWS_REGION) is required for the agentic delegate");
    }
    this.client = config.client ?? new KMSClient({ region });
  }

  private async publicKey(): Promise<PublicKey> {
    if (this.cachedPublicKey) return this.cachedPublicKey;
    const response = await this.client.send(new GetPublicKeyCommand({ KeyId: this.keyId }));
    if (!response.PublicKey) throw new Error("KMS agentic delegate returned no public key");
    this.cachedPublicKey = new PublicKey(
      spkiToEd25519PublicKey(new Uint8Array(response.PublicKey)),
    );
    return this.cachedPublicKey;
  }

  async getPublicKey(): Promise<string> {
    return (await this.publicKey()).toBase58();
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array) || message.length === 0 || message.length > 4_096) {
      throw new AgenticAuthorizationError("bad_delegate_message");
    }
    const response = await this.client.send(new SignCommand({
      KeyId: this.keyId,
      Message: message,
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    }));
    if (!response.Signature) throw new Error("KMS agentic delegate returned no signature");
    const signature = new Uint8Array(response.Signature);
    if (signature.length !== nacl.sign.signatureLength) {
      throw new Error(`KMS agentic delegate signature length ${signature.length}, expected 64`);
    }
    const publicKey = await this.publicKey();
    if (!nacl.sign.detached.verify(message, signature, publicKey.toBytes())) {
      throw new Error("KMS agentic delegate signature failed local verification");
    }
    return signature;
  }
}

/** Build the envelope after a social event has been parsed into one exact action. */
export async function signSolanaAgenticIntent(input: {
  grant: SolanaAgenticGrantDefinitionV1;
  grantSignature: string;
  intent: SolanaAgenticActionPayloadV1;
  signer: AgenticDelegateSigner;
}): Promise<SolanaAgenticEnvelopeV1> {
  const signerPublicKey = await input.signer.getPublicKey();
  if (signerPublicKey !== input.grant.sessionDelegate) {
    throw new AgenticAuthorizationError("delegate_key_mismatch");
  }
  const bytes = solanaAgenticActionBytes(input.intent);
  const signature = await input.signer.sign(bytes);
  if (!nacl.sign.detached.verify(bytes, signature, new PublicKey(signerPublicKey).toBytes())) {
    throw new AgenticAuthorizationError("invalid_delegate_signature");
  }
  return {
    version: 1,
    grant: input.grant,
    grantSignature: input.grantSignature,
    intent: input.intent,
    intentSignature: Buffer.from(signature).toString("base64"),
  };
}
