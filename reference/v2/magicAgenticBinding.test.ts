import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import { AgenticAuthorizationError } from "./agenticAuthorization.js";
import { resolveMagicSolanaWalletBinding } from "./magicAgenticBinding.js";
import { createUser, makeTestDb } from "./testdb.js";

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticAuthorizationError && error.code === code
  ));
}

async function dbWithMagicColumns() {
  const db = await makeTestDb();
  // These columns are owned by codex/beta-magic-migration and intentionally
  // are not duplicated in this branch's production migration.
  await db.exec(`
    ALTER TABLE users ADD COLUMN magic_issuer TEXT;
    ALTER TABLE users ADD COLUMN solana_wallet_address TEXT;
  `);
  return db;
}

test("returns only the server-persisted Magic Solana wallet", async () => {
  const db = await dbWithMagicColumns();
  const userId = await createUser(db, "magic-bound", "10");
  const wallet = Keypair.generate().publicKey.toBase58();
  await db.query(
    `UPDATE users SET magic_issuer=$1,solana_wallet_address=$2 WHERE id=$3::uuid`,
    ["did:ethr:magic-user", wallet, userId],
  );
  assert.deepEqual(await resolveMagicSolanaWalletBinding(db, userId), {
    wallet,
    provider: "magic",
  });
});

test("fails closed for missing identity, wallet, malformed wallet and banned user", async () => {
  const db = await dbWithMagicColumns();
  const userId = await createUser(db, "magic-unbound", "10");
  await expectCode("magic_identity_not_linked", () => (
    resolveMagicSolanaWalletBinding(db, userId)
  ));
  await db.query(`UPDATE users SET magic_issuer=$1 WHERE id=$2::uuid`, ["did:magic:user", userId]);
  await expectCode("magic_solana_wallet_not_linked", () => (
    resolveMagicSolanaWalletBinding(db, userId)
  ));
  await db.query(`UPDATE users SET solana_wallet_address='not-a-wallet' WHERE id=$1::uuid`, [userId]);
  await expectCode("bad_magic_solana_wallet", () => (
    resolveMagicSolanaWalletBinding(db, userId)
  ));
  await db.query(
    `UPDATE users SET solana_wallet_address=$1,banned=TRUE WHERE id=$2::uuid`,
    [Keypair.generate().publicKey.toBase58(), userId],
  );
  await expectCode("identity_user_blocked", () => (
    resolveMagicSolanaWalletBinding(db, userId)
  ));
});
