-- Initial schema for near.email database

-- Emails table (inbox)
CREATE TABLE IF NOT EXISTS emails (
    id UUID PRIMARY KEY,
    recipient TEXT NOT NULL,
    sender_email TEXT NOT NULL,
    encrypted_data BYTEA NOT NULL,
    received_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient);
CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at DESC);

-- Sent emails table
CREATE TABLE IF NOT EXISTS sent_emails (
    id UUID PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    encrypted_data BYTEA NOT NULL,
    tx_hash TEXT,
    sent_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sent_emails_sender ON sent_emails(sender);
CREATE INDEX IF NOT EXISTS idx_sent_emails_sent_at ON sent_emails(sent_at DESC);
