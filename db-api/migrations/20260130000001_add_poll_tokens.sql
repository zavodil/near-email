-- Poll tokens for lightweight email count checking without full authentication
-- Token = SHA256(account_id + poll_secret + random_salt)
-- Used by /poll/count public endpoint

CREATE TABLE IF NOT EXISTS poll_tokens (
    token VARCHAR(64) PRIMARY KEY,
    account_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for looking up by account_id (used when generating new token to delete old one)
CREATE INDEX IF NOT EXISTS idx_poll_tokens_account ON poll_tokens(account_id);
