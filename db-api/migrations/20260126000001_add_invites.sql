-- Invite system for near.email
-- Creates scarcity/exclusivity like Friend.tech (3 invites per user)
--
-- ADMIN COMMANDS (run via psql or db-api endpoints):
--
-- 1. Seed a user (register without invite):
--    curl -X POST http://localhost:8080/admin/invites/seed-user \
--      -H "Content-Type: application/json" \
--      -H "X-API-Secret: your-secret" \
--      -d '{"account_id": "alice.near", "base_invites": 10}'
--
-- 2. Grant bonus invites to existing user:
--    curl -X POST http://localhost:8080/admin/invites/grant \
--      -H "Content-Type: application/json" \
--      -H "X-API-Secret: your-secret" \
--      -d '{"account_id": "alice.near", "amount": 5}'
--
-- 3. Direct SQL to seed user:
--    INSERT INTO registered_users (account_id) VALUES ('alice.near');
--    INSERT INTO invite_allowance (account_id, base_invites) VALUES ('alice.near', 10);
--
-- 4. Direct SQL to grant bonus invites:
--    UPDATE invite_allowance SET bonus_invites = bonus_invites + 5 WHERE account_id = 'alice.near';
--
-- 5. Disable invite system entirely:
--    UPDATE invite_settings SET value = 'false' WHERE key = 'invites_enabled';
--

-- Registered users (gating access to the service)
CREATE TABLE IF NOT EXISTS registered_users (
    account_id TEXT PRIMARY KEY,
    invited_by TEXT,                    -- who invited them (null for seed users)
    invite_code TEXT,                   -- which code they used
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registered_users_invited_by ON registered_users(invited_by);

-- Invite allowance per user
CREATE TABLE IF NOT EXISTS invite_allowance (
    account_id TEXT PRIMARY KEY,
    base_invites INT NOT NULL DEFAULT 3,   -- default invites for new users
    bonus_invites INT NOT NULL DEFAULT 0,  -- extra invites granted by admin
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Invite codes
CREATE TABLE IF NOT EXISTS invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT UNIQUE NOT NULL,
    owner_account_id TEXT NOT NULL,       -- who created this invite
    recipient_email TEXT,                  -- null if just a code (not sent via email)
    used_by_account_id TEXT,               -- null if not used yet
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL        -- 7 days from creation
);

CREATE INDEX IF NOT EXISTS idx_invites_owner ON invites(owner_account_id);
CREATE INDEX IF NOT EXISTS idx_invites_code ON invites(code);
CREATE INDEX IF NOT EXISTS idx_invites_expires_at ON invites(expires_at);

-- Global settings for invite system
CREATE TABLE IF NOT EXISTS invite_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default settings
INSERT INTO invite_settings (key, value) VALUES
    ('default_base_invites', '3'),
    ('invite_expiry_days', '7'),
    ('invites_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
