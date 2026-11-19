-- Tables use the ict_ prefix so other sites can share this database safely.
CREATE TABLE IF NOT EXISTS ict_users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  pass_salt TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ict_users_username_lower ON ict_users (lower(username));
CREATE TABLE IF NOT EXISTS ict_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES ict_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS ict_progress (
  user_id BIGINT PRIMARY KEY REFERENCES ict_users(id) ON DELETE CASCADE,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ict_certificates (
  id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES ict_users(id) ON DELETE CASCADE,
  program TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, program)
);
