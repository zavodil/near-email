//! Database API client for near.email WASI module
//!
//! Communicates with the database via HTTP API (since WASI can't do direct DB connections)

use crate::types::*;
use std::time::Duration;
use wasi_http_client::Client;

/// HTTP request timeout
const TIMEOUT: Duration = Duration::from_secs(30);

/// Fetch encrypted emails for an account
pub fn fetch_emails(
    api_url: &str,
    account_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<EncryptedEmail>, Box<dyn std::error::Error>> {
    let url = format!(
        "{}/emails?recipient={}&limit={}&offset={}",
        api_url, account_id, limit, offset
    );

    let response = Client::new()
        .get(&url)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() != 200 {
        return Err(format!("Database API error: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: DbEmailsResponse = serde_json::from_slice(&body)?;

    Ok(result.emails)
}

/// Send email via SMTP relay
#[allow(dead_code)]
pub fn send_email(
    api_url: &str,
    from_account: &str,
    to: &str,
    subject: &str,
    body_text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    send_email_with_attachments(api_url, from_account, to, subject, body_text, &[])
}

/// Send email with attachments via SMTP relay
///
/// Uses chunked HTTP writes to bypass the 4KB limit in wasi-http's blocking_write_and_flush
pub fn send_email_with_attachments(
    api_url: &str,
    from_account: &str,
    to: &str,
    subject: &str,
    body_text: &str,
    attachments: &[crate::types::Attachment],
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/send", api_url);
    eprintln!("[send_email] url={}, attachments={}", url, attachments.len());

    let payload = serde_json::json!({
        "from_account": from_account,
        "to": to,
        "subject": subject,
        "body": body_text,
        "attachments": attachments,
    });

    let body_data = serde_json::to_vec(&payload)?;
    eprintln!("[send_email] body_len={} bytes ({} KB)", body_data.len(), body_data.len() / 1024);

    // Use chunked HTTP client for large bodies (bypasses 4KB limit)
    let response = crate::http_chunked::post_chunked(
        &url,
        "application/json",
        &body_data,
        TIMEOUT,
    )?;

    eprintln!("[send_email] response status={}", response.status());

    if response.status() != 200 {
        let body_str = String::from_utf8_lossy(response.body());
        return Err(format!("Send email failed: {} - {}", response.status(), body_str).into());
    }

    Ok(())
}

/// Delete email from database
pub fn delete_email(
    api_url: &str,
    email_id: &str,
    account_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let url = format!("{}/emails/{}", api_url, email_id);

    let payload = serde_json::json!({
        "account_id": account_id,
    });

    let body_data = serde_json::to_vec(&payload)?;
    let response = Client::new()
        .delete(&url)
        .header("Content-Type", "application/json")
        .body(&body_data)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() != 200 {
        return Err(format!("Delete email failed: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: DbGenericResponse = serde_json::from_slice(&body)?;

    Ok(result.deleted)
}

/// Count emails for account
pub fn count_emails(
    api_url: &str,
    account_id: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let url = format!("{}/emails/count?recipient={}", api_url, account_id);

    let response = Client::new()
        .get(&url)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() != 200 {
        return Err(format!("Count emails failed: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: DbCountResponse = serde_json::from_slice(&body)?;

    Ok(result.count)
}

/// Store internal email (already encrypted)
/// Used for NEAR-to-NEAR messaging without external SMTP
pub fn store_internal_email(
    api_url: &str,
    recipient: &str,
    sender_email: &str,
    encrypted_data: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let url = format!("{}/internal-store", api_url);

    let payload = serde_json::json!({
        "recipient": recipient,
        "sender_email": sender_email,
        "encrypted_data": STANDARD.encode(encrypted_data),
    });

    let body_data = serde_json::to_vec(&payload)?;

    // Use chunked HTTP for large bodies
    let response = crate::http_chunked::post_chunked(
        &url,
        "application/json",
        &body_data,
        TIMEOUT,
    )?;

    if response.status() != 200 {
        return Err(format!("Store internal email failed: {}", response.status()).into());
    }

    // Parse response to get the email ID
    let result: serde_json::Value = serde_json::from_slice(response.body())?;
    let id = result["id"].as_str().unwrap_or("unknown").to_string();

    Ok(id)
}

/// Fetch encrypted sent emails for an account
pub fn fetch_sent_emails(
    api_url: &str,
    account_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<EncryptedSentEmail>, Box<dyn std::error::Error>> {
    let url = format!(
        "{}/sent-emails?sender={}&limit={}&offset={}",
        api_url, account_id, limit, offset
    );

    let response = Client::new()
        .get(&url)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() != 200 {
        return Err(format!("Database API error: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: DbSentEmailsResponse = serde_json::from_slice(&body)?;

    Ok(result.emails)
}

/// Store sent email (already encrypted)
/// If `email_id` is provided, the database will use it; otherwise it generates a new UUID.
/// This is used for lazy attachment support where we need to pre-store attachments with the email_id.
pub fn store_sent_email(
    api_url: &str,
    sender: &str,
    recipient_email: &str,
    encrypted_data: &[u8],
    tx_hash: Option<&str>,
    email_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let url = format!("{}/store-sent", api_url);

    let payload = serde_json::json!({
        "sender": sender,
        "recipient_email": recipient_email,
        "encrypted_data": STANDARD.encode(encrypted_data),
        "tx_hash": tx_hash,
        "id": email_id,
    });

    let body_data = serde_json::to_vec(&payload)?;

    // Use chunked HTTP for large bodies
    let response = crate::http_chunked::post_chunked(
        &url,
        "application/json",
        &body_data,
        TIMEOUT,
    )?;

    if response.status() != 200 {
        return Err(format!("Store sent email failed: {}", response.status()).into());
    }

    let result: DbStoreSentResponse = serde_json::from_slice(response.body())?;

    Ok(result.id)
}

/// Count sent emails for account
pub fn count_sent_emails(
    api_url: &str,
    account_id: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let url = format!("{}/sent-emails/count?sender={}", api_url, account_id);

    let response = Client::new()
        .get(&url)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() != 200 {
        return Err(format!("Count sent emails failed: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: DbCountResponse = serde_json::from_slice(&body)?;

    Ok(result.count)
}

/// Store an attachment for lazy loading
pub fn store_attachment(
    api_url: &str,
    email_id: &str,
    folder: &str,
    recipient: &str,
    filename: &str,
    content_type: &str,
    size: usize,
    encrypted_data: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let url = format!("{}/attachments", api_url);

    let payload = serde_json::json!({
        "email_id": email_id,
        "folder": folder,
        "recipient": recipient,
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "encrypted_data": STANDARD.encode(encrypted_data),
    });

    let body_data = serde_json::to_vec(&payload)?;

    // Use chunked HTTP for large bodies (attachments can be big)
    let response = crate::http_chunked::post_chunked(
        &url,
        "application/json",
        &body_data,
        TIMEOUT,
    )?;

    if response.status() != 200 {
        return Err(format!("Store attachment failed: {}", response.status()).into());
    }

    let result: crate::types::DbStoreAttachmentResponse = serde_json::from_slice(response.body())?;

    Ok(result.id)
}

/// Fetch an attachment by ID
pub fn fetch_attachment(
    api_url: &str,
    attachment_id: &str,
    recipient: &str,
) -> Result<crate::types::DbAttachmentResponse, Box<dyn std::error::Error>> {
    let url = format!("{}/attachments/{}?recipient={}", api_url, attachment_id, recipient);

    let response = Client::new()
        .get(&url)
        .connect_timeout(TIMEOUT)
        .send()?;

    if response.status() == 404 {
        return Err("Attachment not found".into());
    }

    if response.status() != 200 {
        return Err(format!("Fetch attachment failed: {}", response.status()).into());
    }

    let body = response.body()?;
    let result: crate::types::DbAttachmentResponse = serde_json::from_slice(&body)?;

    Ok(result)
}
