-- Reference-only schema excerpt from FUDmarkets V1.
-- Do not run this file from FUD-agent. FUDmarkets remains the schema owner.

ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id BIGINT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_username TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS x_username TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS x_user_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_x_user_id
  ON users (x_user_id)
  WHERE x_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS x_oauth_tokens (
  oauth_token        TEXT PRIMARY KEY,
  oauth_token_secret TEXT NOT NULL,
  user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tg_link_tokens (
  token      TEXT PRIMARY KEY,
  tg_id      BIGINT,
  user_id    UUID,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS bot_kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
