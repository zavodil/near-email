//! Database operations for near.email

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Email record in database
#[derive(Debug, Clone)]
pub struct EmailRecord {
    pub id: Uuid,
    pub recipient: String,
    pub sender_email: String,
    pub subject_hint: Option<String>,
    pub encrypted_data: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

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

/// Get emails for a recipient (encrypted)
pub async fn get_emails_for_recipient(
    pool: &PgPool,
    recipient: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<EmailRecord>> {
    let records = sqlx::query_as!(
        EmailRecord,
        r#"
        SELECT id, recipient, sender_email, subject_hint, encrypted_data, received_at
        FROM emails
        WHERE recipient = $1
        ORDER BY received_at DESC
        LIMIT $2 OFFSET $3
        "#,
        recipient,
        limit,
        offset
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// Mark emails as fetched
pub async fn mark_emails_fetched(pool: &PgPool, ids: &[Uuid]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }

    sqlx::query(
        r#"
        UPDATE emails
        SET fetched_at = NOW()
        WHERE id = ANY($1)
        "#,
    )
    .bind(ids)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete email by id (for owner only)
pub async fn delete_email(pool: &PgPool, id: Uuid, recipient: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM emails
        WHERE id = $1 AND recipient = $2
        "#,
    )
    .bind(id)
    .bind(recipient)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Count emails for recipient
pub async fn count_emails(pool: &PgPool, recipient: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM emails WHERE recipient = $1
        "#,
    )
    .bind(recipient)
    .fetch_one(pool)
    .await?;

    Ok(count.0)
}
