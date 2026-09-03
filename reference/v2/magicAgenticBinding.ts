import { PublicKey } from "@solana/web3.js";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import type { Queryable } from "./dbClient.js";
import type { AgenticWalletBinding } from "./agenticExecution.js";

type MagicBindingRow = {
  magic_issuer: string | null;
  solana_wallet_address: string | null;
  banned: boolean;
};

/**
 * Adapter contract for `codex/beta-magic-migration`. The migration owns these
 * user columns; agentic execution only reads the server-verified durable bind.
 */
export async function resolveMagicSolanaWalletBinding(
  db: Queryable,
  userId: string,
): Promise<AgenticWalletBinding> {
  const selected = await db.query<MagicBindingRow>(
    `SELECT magic_issuer,solana_wallet_address,banned
       FROM users
      WHERE id=$1::uuid`,
    [userId],
  );
  const row = selected.rows[0];
  if (!row) throw new AgenticAuthorizationError("agentic_user_not_found");
  if (row.banned) throw new AgenticAuthorizationError("identity_user_blocked");
  if (!row.magic_issuer?.trim()) {
    throw new AgenticAuthorizationError("magic_identity_not_linked");
  }
  if (!row.solana_wallet_address?.trim()) {
    throw new AgenticAuthorizationError("magic_solana_wallet_not_linked");
  }
  const encoded = row.solana_wallet_address.trim();
  try {
    const wallet = new PublicKey(encoded);
    if (wallet.toBase58() !== encoded) throw new Error("non-canonical wallet");
  } catch {
    throw new AgenticAuthorizationError("bad_magic_solana_wallet");
  }
  return { wallet: encoded, provider: "magic" };
}
