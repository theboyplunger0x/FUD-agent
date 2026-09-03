import assert from "node:assert/strict";
import test from "node:test";
import { AgenticIdentityError, resolveAgenticIdentity } from "./agenticIdentity.js";
import { createUser, makeTestDb } from "./testdb.js";

async function expectCode(code: string, operation: () => Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error: unknown) => (
    error instanceof AgenticIdentityError && error.code === code
  ));
}

test("X resolves only by immutable provider id, never by mutable username", async () => {
  const db = await makeTestDb();
  const userId = await createUser(db, "linked-x", "10");
  await db.query(`UPDATE users SET x_user_id=$1,x_username=$2 WHERE id=$3`, ["123456789", "fuduser", userId]);
  assert.deepEqual(await resolveAgenticIdentity(db, { channel: "x", externalId: "123456789" }), {
    userId,
    channel: "x",
    externalIdentity: "x:123456789",
    username: "linked-x",
  });
  await expectCode("bad_external_identity", () => resolveAgenticIdentity(db, {
    channel: "x",
    externalId: "fuduser",
  }));
});

test("Telegram resolves by numeric telegram_id", async () => {
  const db = await makeTestDb();
  const userId = await createUser(db, "linked-tg", "10");
  await db.query(`UPDATE users SET telegram_id=$1::bigint WHERE id=$2`, ["987654321", userId]);
  const resolved = await resolveAgenticIdentity(db, { channel: "telegram", externalId: "987654321" });
  assert.equal(resolved.userId, userId);
  assert.equal(resolved.externalIdentity, "telegram:987654321");
});

test("unlinked and banned identities fail closed", async () => {
  const db = await makeTestDb();
  await expectCode("identity_not_linked", () => resolveAgenticIdentity(db, {
    channel: "x",
    externalId: "111",
  }));
  const userId = await createUser(db, "blocked-x", "10");
  await db.query(`UPDATE users SET x_user_id='222',banned=TRUE WHERE id=$1`, [userId]);
  await expectCode("identity_user_blocked", () => resolveAgenticIdentity(db, {
    channel: "x",
    externalId: "222",
  }));
});
