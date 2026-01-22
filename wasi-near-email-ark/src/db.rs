//! Database API client for near.email WASI module
//!
//! Communicates with the database via HTTP API (since WASI can't do direct DB connections)

use crate::types::*;
use wasi_http_client::{Client, Method, Request};

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

    let client = Client::new();
    let request = Request::new(Method::Get, &url);
    let response = client.send(request)?;

    if response.status() != 200 {
        return Err(format!("Database API error: {}", response.status()).into());
    }

    let body = response.body();
    let result: DbEmailsResponse = serde_json::from_slice(body)?;

    Ok(result.emails)
}

/// Send email via SMTP relay
pub fn send_email(
    api_url: &str,
    from_account: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/send", api_url);

    let payload = serde_json::json!({
        "from_account": from_account,
        "to": to,
        "subject": subject,
        "body": body,
    });

    let client = Client::new();
    let request = Request::new(Method::Post, &url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&payload)?);

    let response = client.send(request)?;

    if response.status() != 200 {
        return Err(format!("Send email failed: {}", response.status()).into());
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

    let client = Client::new();
    let request = Request::new(Method::Delete, &url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&payload)?);

    let response = client.send(request)?;

    if response.status() != 200 {
        return Err(format!("Delete email failed: {}", response.status()).into());
    }

    let body = response.body();
    let result: DbGenericResponse = serde_json::from_slice(body)?;

    Ok(result.deleted)
}

/// Count emails for account
pub fn count_emails(
    api_url: &str,
    account_id: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let url = format!("{}/emails/count?recipient={}", api_url, account_id);

    let client = Client::new();
    let request = Request::new(Method::Get, &url);
    let response = client.send(request)?;

    if response.status() != 200 {
        return Err(format!("Count emails failed: {}", response.status()).into());
    }

    let body = response.body();
    let result: DbCountResponse = serde_json::from_slice(body)?;

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

    let client = Client::new();
    let request = Request::new(Method::Post, &url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&payload)?);

    let response = client.send(request)?;

    if response.status() != 200 {
        return Err(format!("Store internal email failed: {}", response.status()).into());
    }

    // Parse response to get the email ID
    let body = response.body();
    let result: serde_json::Value = serde_json::from_slice(body)?;
    let id = result["id"].as_str().unwrap_or("unknown").to_string();

    Ok(id)
}
