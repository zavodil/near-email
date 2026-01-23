-- Attachments table for lazy loading large attachments
-- Attachments >= 2KB are stored separately and loaded on demand
-- Encrypted with recipient's derived key

CREATE TABLE IF NOT EXISTS attachments (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL,  -- Reference to emails.id or sent_emails.id
    folder TEXT NOT NULL DEFAULT 'inbox',  -- 'inbox' or 'sent'
    recipient TEXT NOT NULL,  -- Account that can access this attachment
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    encrypted_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attachments_recipient ON attachments(recipient);
