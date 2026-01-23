//! Database operations for near.email

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// Run database migrations
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emails (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            recipient VARCHAR(64) NOT NULL,
            sender_email VARCHAR(255) NOT NULL,
            subject_hint VARCHAR(255),
            encrypted_data BYTEA NOT NULL,
            received_at TIMESTAMPTZ DEFAULT NOW(),
            fetched_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    // Sent emails table - stores encrypted copies of sent emails
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sent_emails (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            sender VARCHAR(64) NOT NULL,
            recipient_email VARCHAR(255) NOT NULL,
            encrypted_data BYTEA NOT NULL,
            tx_hash VARCHAR(64),
            sent_at TIMESTAMPTZ DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_sent_emails_sender ON sent_emails(sender)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_sent_emails_sent_at ON sent_emails(sent_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Store encrypted email in database
pub async fn store_email(
    pool: &PgPool,
    recipient: &str,
    sender_email: &str,
    subject_hint: Option<&str>,
    encrypted_data: &[u8],
) -> Result<Uuid> {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO emails (id, recipient, sender_email, subject_hint, encrypted_data)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(recipient)
    .bind(sender_email)
    .bind(subject_hint)
    .bind(encrypted_data)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Store encrypted sent email in database
pub async fn store_sent_email(
    pool: &PgPool,
    sender: &str,
    recipient_email: &str,
    encrypted_data: &[u8],
    tx_hash: Option<&str>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO sent_emails (id, sender, recipient_email, encrypted_data, tx_hash)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(sender)
    .bind(recipient_email)
    .bind(encrypted_data)
    .bind(tx_hash)
    .execute(pool)
    .await?;

    Ok(id)
}
