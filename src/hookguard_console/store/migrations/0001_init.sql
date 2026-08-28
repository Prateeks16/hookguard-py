CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,              -- PHC string: $argon2id$v=19$m=65536,t=3,p=2$...
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL            -- unix ms, everywhere
);

CREATE TABLE sessions (
  id           INTEGER PRIMARY KEY,
  token_hash   BLOB NOT NULL UNIQUE,        -- sha256(cookie token)
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token   TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,            -- absolute cap
  ip           TEXT,
  user_agent   TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE endpoints (                     -- a Route, DB-backed
  id            INTEGER PRIMARY KEY,
  path          TEXT NOT NULL UNIQUE,        -- "/hook/stripe"
  provider      TEXT NOT NULL CHECK (provider IN ('stripe','github','shopify','paypal')),
  upstream_url  TEXT NOT NULL,
  replay_window TEXT NOT NULL DEFAULT '',    -- Go duration string ("5m") or ''
  secret_env    TEXT NOT NULL DEFAULT '',    -- NAME of env var; never the secret
  webhook_id    TEXT NOT NULL DEFAULT '',    -- PayPal only; config, not a secret
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  CHECK ((provider = 'paypal' AND webhook_id <> '' AND secret_env  = '')
      OR (provider <> 'paypal' AND secret_env <> '' AND webhook_id = ''))
);

CREATE TABLE events (                        -- one row per gateway verdict
  id              INTEGER PRIMARY KEY,
  received_at     INTEGER NOT NULL,          -- gateway ts, unix ms
  path            TEXT NOT NULL,
  provider        TEXT NOT NULL,
  verdict         TEXT NOT NULL CHECK (verdict IN ('accepted','rejected')),
  reason          TEXT NOT NULL DEFAULT '',  -- '' when accepted
  upstream_status INTEGER NOT NULL DEFAULT 0,
  latency_ms      INTEGER NOT NULL DEFAULT 0,
  body_bytes      INTEGER NOT NULL DEFAULT 0,
  body_sha256     TEXT NOT NULL DEFAULT '',
  remote_ip       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX events_time     ON events(received_at DESC);
CREATE INDEX events_verdict  ON events(verdict, received_at DESC);
CREATE INDEX events_provider ON events(provider, received_at DESC);

CREATE TABLE event_rollups (                 -- hourly, upserted at ingest
  hour     INTEGER NOT NULL,                 -- unix hour bucket
  provider TEXT    NOT NULL,
  verdict  TEXT    NOT NULL,
  n        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, provider, verdict)
);

CREATE TABLE auth_events (
  id         INTEGER PRIMARY KEY,
  at         INTEGER NOT NULL,
  user_id    INTEGER,                        -- nullable: failed logins
  email      TEXT NOT NULL DEFAULT '',
  kind       TEXT NOT NULL,                  -- login_ok|login_fail|logout|pw_change|session_revoke|user_create
  ip         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE settings (                      -- instance key/value (retention_days=30, …)
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
