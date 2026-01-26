-- Blacklist for banned accounts and email statistics
--
-- ADMIN COMMANDS:
--
-- 1. Add account to blacklist:
--    curl -X POST http://localhost:8080/admin/blacklist/add \
--      -H "Content-Type: application/json" \
--      -H "X-API-Secret: your-secret" \
--      -d '{"account_id": "spammer.near", "reason": "Spam abuse"}'
--
-- 2. Remove from blacklist:
--    curl -X POST http://localhost:8080/admin/blacklist/remove \
--      -H "Content-Type: application/json" \
--      -H "X-API-Secret: your-secret" \
--      -d '{"account_id": "spammer.near"}'
--
-- 3. Check if account is blacklisted:
--    curl "http://localhost:8080/admin/blacklist/check?account_id=spammer.near" \
--      -H "X-API-Secret: your-secret"
--
-- 4. Direct SQL to blacklist:
--    INSERT INTO blacklist (account_id, reason) VALUES ('spammer.near', 'Spam abuse');
--
-- 5. Direct SQL to remove from blacklist:
--    DELETE FROM blacklist WHERE account_id = 'spammer.near';
--

-- Blacklisted accounts (cannot use the service)
CREATE TABLE IF NOT EXISTS blacklist (
    account_id TEXT PRIMARY KEY,
    reason TEXT,                         -- optional reason for blacklisting
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT                      -- admin who added them
);

-- Email statistics per account
CREATE TABLE IF NOT EXISTS email_stats (
    account_id TEXT PRIMARY KEY,
    emails_received INT NOT NULL DEFAULT 0,   -- incoming emails stored
    emails_sent INT NOT NULL DEFAULT 0,       -- outgoing emails sent
    last_received_at TIMESTAMPTZ,
    last_sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_blacklist_created_at ON blacklist(created_at);
CREATE INDEX IF NOT EXISTS idx_email_stats_sent ON email_stats(emails_sent DESC);
CREATE INDEX IF NOT EXISTS idx_email_stats_received ON email_stats(emails_received DESC);
