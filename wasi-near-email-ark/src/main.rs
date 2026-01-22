//! OutLayer WASI module for near.email
//!
//! Decrypts emails for NEAR account owners by:
//! 1. Deriving private key from master key + account_id
//! 2. Fetching encrypted emails from database
//! 3. Decrypting and returning plaintext emails
//!
//! Note: No signature verification needed - emails are encrypted per-account,
//! only TEE with master key can decrypt.

mod crypto;
mod db;
#[allow(dead_code)]
mod near; // Keep for potential future use
mod types;

use outlayer::{env, storage};
use types::*;

fn main() {
    // Force storage interface import by actually calling it (required for project context)
    // This ensures the linker includes the near:storage/api interface
    let _ = storage::has("_init");

    let result = process();

    match result {
        Ok(response) => {
            let _ = env::output_json(&response);
        }
        Err(e) => {
            let error_response = ErrorResponse {
                success: false,
                error: e.to_string(),
            };
            let _ = env::output_json(&error_response);
        }
    }
}

fn process() -> Result<Response, Box<dyn std::error::Error>> {
    // Read raw input for debugging
    let raw_input = env::input();
    let raw_str = String::from_utf8_lossy(&raw_input);
    eprintln!("DEBUG raw input: {}", raw_str);

    // Parse input
    let input: Request = serde_json::from_slice(&raw_input)
        .map_err(|e| format!("Failed to parse input: {}. Raw: {}", e, raw_str))?;

    // Get master private key from secrets (PRIVATE_ prefix for OutLayer private secrets)
    let master_privkey_hex = std::env::var("PROTECTED_MASTER_KEY")
        .map_err(|_| "PROTECTED_MASTER_KEY not configured")?;

    let master_privkey = crypto::parse_private_key(&master_privkey_hex)?;

    // Helper to get database API URL (lazy, only when needed)
    let get_db_api_url = || -> Result<String, Box<dyn std::error::Error>> {
        std::env::var("DATABASE_API_URL")
            .map_err(|_| "DATABASE_API_URL not configured".into())
    };

    // Default account suffix (.near for mainnet, .testnet for testnet)
    let default_account_suffix = std::env::var("DEFAULT_ACCOUNT_SUFFIX")
        .unwrap_or_else(|_| ".near".to_string());

    // Get authenticated signer from OutLayer (set by blockchain transaction)
    // This is the account that signed the transaction to outlayer contract
    let get_signer = || -> Result<String, Box<dyn std::error::Error>> {
        env::signer_account_id()
            .ok_or_else(|| "No signer account - must be called via NEAR transaction".into())
    };

    match input {
        Request::GetEmails {
            ephemeral_pubkey,
            limit,
            offset,
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            // Get authenticated signer
            let account_id = get_signer()?;

            // Parse client's ephemeral public key (hex -> bytes)
            let ephemeral_pubkey_bytes = hex::decode(&ephemeral_pubkey)
                .map_err(|e| format!("Invalid ephemeral_pubkey hex: {}", e))?;

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Fetch encrypted emails from database
            let encrypted_emails = db::fetch_emails(
                &get_db_api_url()?,
                &account_id,
                limit.unwrap_or(50),
                offset.unwrap_or(0),
            )?;

            // Decrypt emails
            let mut emails = Vec::new();
            for enc_email in encrypted_emails {
                match crypto::decrypt_email(&user_privkey, &enc_email.encrypted_data) {
                    Ok(decrypted) => {
                        // Parse email content
                        let parsed = parse_email(&decrypted)?;
                        emails.push(Email {
                            id: enc_email.id,
                            from: enc_email.sender_email,
                            subject: parsed.subject,
                            body: parsed.body,
                            received_at: enc_email.received_at,
                        });
                    }
                    Err(e) => {
                        // Log decryption error but continue with other emails
                        eprintln!("Failed to decrypt email {}: {}", enc_email.id, e);
                    }
                }
            }

            // Serialize emails to JSON
            let emails_json = serde_json::to_vec(&emails)?;

            // Re-encrypt with client's ephemeral public key
            // This ensures the response is only readable by the client
            let encrypted_response = ecies::encrypt(&ephemeral_pubkey_bytes, &emails_json)
                .map_err(|e| format!("Failed to encrypt response: {}", e))?;

            Ok(Response::GetEmails(GetEmailsResponse {
                success: true,
                encrypted_emails: STANDARD.encode(&encrypted_response),
            }))
        }

        Request::SendEmail {
            to,
            subject,
            body,
        } => {
            // Get authenticated signer
            let account_id = get_signer()?;

            // Check if internal email (@near.email)
            let internal_suffix = "@near.email";
            if to.to_lowercase().ends_with(internal_suffix) {
                // Internal email - encrypt and store directly
                let recipient_account = extract_account_from_email(&to, internal_suffix, &default_account_suffix);

                // Build email content (simple format)
                let email_content = format!(
                    "From: {}@near.email\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
                    account_id, to, subject, body
                );

                // Encrypt for recipient
                let encrypted = crypto::encrypt_for_account(
                    &master_privkey,
                    &recipient_account,
                    email_content.as_bytes(),
                )?;

                // Store in database
                let sender_email = format!("{}@near.email", account_id);
                let email_id = db::store_internal_email(
                    &get_db_api_url()?,
                    &recipient_account,
                    &sender_email,
                    &encrypted,
                )?;

                Ok(Response::SendEmail(SendEmailResponse {
                    success: true,
                    message_id: Some(email_id),
                }))
            } else {
                // External email - send via SMTP relay
                db::send_email(&get_db_api_url()?, &account_id, &to, &subject, &body)?;

                Ok(Response::SendEmail(SendEmailResponse {
                    success: true,
                    message_id: None,
                }))
            }
        }

        Request::DeleteEmail {
            email_id,
        } => {
            // Get authenticated signer
            let account_id = get_signer()?;

            // Delete email from database
            let deleted = db::delete_email(&get_db_api_url()?, &email_id, &account_id)?;

            Ok(Response::DeleteEmail(DeleteEmailResponse {
                success: true,
                deleted,
            }))
        }

        Request::GetEmailCount => {
            // Get authenticated signer
            let account_id = get_signer()?;

            // Get email count
            let count = db::count_emails(&get_db_api_url()?, &account_id)?;

            Ok(Response::GetEmailCount(GetEmailCountResponse {
                success: true,
                count,
            }))
        }

        Request::GetMasterPublicKey => {
            // Return master public key for SMTP server encryption
            // No authentication needed - public key is safe to share
            let pubkey_hex = crypto::get_master_pubkey(&master_privkey);

            Ok(Response::GetMasterPublicKey(GetMasterPublicKeyResponse {
                success: true,
                public_key: pubkey_hex,
            }))
        }
    }
}

/// Parse decrypted email content
fn parse_email(data: &[u8]) -> Result<ParsedEmail, Box<dyn std::error::Error>> {
    let parsed = mailparse::parse_mail(data)?;

    let subject = parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("subject"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    let body = parsed.get_body()?;

    Ok(ParsedEmail { subject, body })
}

struct ParsedEmail {
    subject: String,
    body: String,
}

/// Extract NEAR account ID from email address
/// e.g., "vadim@near.email" -> "vadim.near" (mainnet) or "vadim.testnet" (testnet)
/// e.g., "vadim.testnet@near.email" -> "vadim.testnet" (explicit)
fn extract_account_from_email(email: &str, email_suffix: &str, default_account_suffix: &str) -> String {
    let email_lower = email.to_lowercase();
    let local_part = email_lower
        .strip_suffix(email_suffix)
        .unwrap_or(&email_lower)
        .to_string();

    // If already has a dot (e.g., vadim.testnet), keep as is
    // Otherwise add default suffix (.near or .testnet)
    if local_part.contains('.') {
        local_part
    } else {
        format!("{}{}", local_part, default_account_suffix)
    }
}
