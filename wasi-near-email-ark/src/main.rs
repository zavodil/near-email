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

    // Email signature template (use %account% for sender's NEAR account)
    let email_signature = std::env::var("EMAIL_SIGNATURE").ok();

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

            // Get signer's public key for encrypting outgoing emails
            let send_pubkey = crypto::derive_user_pubkey(&master_privkey, &account_id)?;
            let send_pubkey_hex = hex::encode(&send_pubkey);

            Ok(Response::GetEmails(GetEmailsResponse {
                success: true,
                encrypted_emails: STANDARD.encode(&encrypted_response),
                send_pubkey: send_pubkey_hex,
            }))
        }

        Request::SendEmail {
            to,
            encrypted_subject,
            encrypted_body,
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            // Get authenticated signer
            let account_id = get_signer()?;

            // Validate sender account - must end with expected suffix (.near/.testnet)
            // This ensures replies can be delivered back to the sender
            validate_sender_account(&account_id, &default_account_suffix)?;

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Decrypt subject and body
            let subject_ciphertext = STANDARD.decode(&encrypted_subject)
                .map_err(|e| format!("Invalid encrypted_subject base64: {}", e))?;
            let body_ciphertext = STANDARD.decode(&encrypted_body)
                .map_err(|e| format!("Invalid encrypted_body base64: {}", e))?;

            let subject_bytes = crypto::decrypt_email(&user_privkey, &subject_ciphertext)?;
            let body_bytes = crypto::decrypt_email(&user_privkey, &body_ciphertext)?;

            let subject = String::from_utf8(subject_bytes)
                .map_err(|e| format!("Invalid UTF-8 in subject: {}", e))?;
            let body = String::from_utf8(body_bytes)
                .map_err(|e| format!("Invalid UTF-8 in body: {}", e))?;

            // Check if internal email (@near.email)
            let internal_suffix = "@near.email";
            // Get tx_hash if available (for blockchain calls)
            let tx_hash = env::transaction_hash();

            // Strip suffix from account_id for email address (zavodil.testnet -> zavodil@near.email)
            let sender_local = account_id
                .strip_suffix(&default_account_suffix)
                .unwrap_or(&account_id);
            let sender_email = format!("{}@near.email", sender_local);

            // Add signature if configured (before quoted text if present)
            let body_with_sig = if let Some(ref sig_template) = email_signature {
                let signature = sig_template.replace("%account%", &account_id);
                insert_signature_before_quote(&body, &signature)
            } else {
                body.clone()
            };

            // Build email content for sent folder (simple format)
            let sent_email_content = format!(
                "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
                sender_email, to, subject, body_with_sig
            );

            // Encrypt email for sender's sent folder
            let encrypted_for_sender = crypto::encrypt_for_account(
                &master_privkey,
                &account_id,
                sent_email_content.as_bytes(),
            )?;

            if to.to_lowercase().ends_with(internal_suffix) {
                // Internal email - encrypt and store directly
                let recipient_account = extract_account_from_email(&to, internal_suffix, &default_account_suffix);

                // Build email content for recipient (same as above)
                let email_content = format!(
                    "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
                    sender_email, to, subject, body_with_sig
                );

                // Encrypt for recipient
                let encrypted = crypto::encrypt_for_account(
                    &master_privkey,
                    &recipient_account,
                    email_content.as_bytes(),
                )?;

                // Store in recipient's inbox
                let email_id = db::store_internal_email(
                    &get_db_api_url()?,
                    &recipient_account,
                    &sender_email,
                    &encrypted,
                )?;

                // Store in sender's sent folder
                let _ = db::store_sent_email(
                    &get_db_api_url()?,
                    &account_id,
                    &to,
                    &encrypted_for_sender,
                    tx_hash.as_deref(),
                );

                Ok(Response::SendEmail(SendEmailResponse {
                    success: true,
                    message_id: Some(email_id),
                }))
            } else {
                // External email - send via SMTP relay
                db::send_email(&get_db_api_url()?, &account_id, &to, &subject, &body)?;

                // Store in sender's sent folder
                let _ = db::store_sent_email(
                    &get_db_api_url()?,
                    &account_id,
                    &to,
                    &encrypted_for_sender,
                    tx_hash.as_deref(),
                );

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

        Request::GetSentEmails {
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

            // Fetch encrypted sent emails from database
            let encrypted_emails = db::fetch_sent_emails(
                &get_db_api_url()?,
                &account_id,
                limit.unwrap_or(50),
                offset.unwrap_or(0),
            )?;

            // Decrypt sent emails
            let mut emails = Vec::new();
            for enc_email in encrypted_emails {
                match crypto::decrypt_email(&user_privkey, &enc_email.encrypted_data) {
                    Ok(decrypted) => {
                        // Parse email content
                        let parsed = parse_email(&decrypted)?;
                        emails.push(SentEmail {
                            id: enc_email.id,
                            to: enc_email.recipient_email,
                            subject: parsed.subject,
                            body: parsed.body,
                            tx_hash: enc_email.tx_hash,
                            sent_at: enc_email.sent_at,
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to decrypt sent email {}: {}", enc_email.id, e);
                    }
                }
            }

            // Serialize emails to JSON
            let emails_json = serde_json::to_vec(&emails)?;

            // Re-encrypt with client's ephemeral public key
            let encrypted_response = ecies::encrypt(&ephemeral_pubkey_bytes, &emails_json)
                .map_err(|e| format!("Failed to encrypt response: {}", e))?;

            Ok(Response::GetSentEmails(GetSentEmailsResponse {
                success: true,
                encrypted_emails: STANDARD.encode(&encrypted_response),
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

    // Try to get body - for simple emails it's in the main part,
    // for multipart emails we need to check subparts
    let body = if parsed.subparts.is_empty() {
        parsed.get_body()?
    } else {
        // Find first text/plain or text/html part
        find_body_part(&parsed).unwrap_or_default()
    };

    Ok(ParsedEmail { subject, body })
}

/// Recursively find text body in email parts
fn find_body_part(mail: &mailparse::ParsedMail) -> Option<String> {
    // Check this part first
    let ctype = mail.ctype.mimetype.to_lowercase();
    if ctype.starts_with("text/plain") || ctype.starts_with("text/html") {
        if let Ok(body) = mail.get_body() {
            if !body.trim().is_empty() {
                return Some(body);
            }
        }
    }

    // Check subparts
    for part in &mail.subparts {
        if let Some(body) = find_body_part(part) {
            return Some(body);
        }
    }

    None
}

struct ParsedEmail {
    subject: String,
    body: String,
}

/// Validate that account_id is allowed to send emails
/// - Must end with the expected suffix (.near for mainnet, .testnet for testnet)
/// - Must NOT be an implicit account (64-char hex)
/// Returns Ok(()) if valid, Err with message if invalid
fn validate_sender_account(account_id: &str, expected_suffix: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Check for implicit accounts (64 hex characters)
    if account_id.len() == 64 && account_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Implicit accounts cannot send emails. Please use a named account ending with {}",
            expected_suffix
        ).into());
    }

    // Check that account ends with expected suffix
    if !account_id.ends_with(expected_suffix) {
        return Err(format!(
            "Account '{}' cannot send emails. Only accounts ending with '{}' are supported. Replies will not be delivered to accounts from other zones.",
            account_id, expected_suffix
        ).into());
    }

    Ok(())
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

/// Insert signature before quoted text markers, or at the end if no quote found
fn insert_signature_before_quote(body: &str, signature: &str) -> String {
    // Common quote markers
    let quote_markers = [
        "-------- Original Message --------",
        "---------- Forwarded message ---------",
        "On ", // "On Mon, Jan 23, 2026 at..." - but need to check it looks like a quote
    ];

    // Find earliest quote marker position
    let mut earliest_pos: Option<usize> = None;

    for marker in &quote_markers[..2] {
        // Check exact markers first
        if let Some(pos) = body.find(marker) {
            earliest_pos = Some(earliest_pos.map_or(pos, |e| e.min(pos)));
        }
    }

    // Check for "On ... wrote:" pattern (common in Gmail replies)
    if let Some(on_pos) = body.find("\nOn ") {
        // Check if this line ends with "wrote:" somewhere after
        let after_on = &body[on_pos..];
        if after_on.contains("wrote:") || after_on.contains("написал:") {
            earliest_pos = Some(earliest_pos.map_or(on_pos, |e| e.min(on_pos)));
        }
    }

    if let Some(pos) = earliest_pos {
        // Insert signature before the quoted text
        let (before, after) = body.split_at(pos);
        let before_trimmed = before.trim_end();
        format!("{}\r\n\r\n--\r\n{}\r\n\r\n{}", before_trimmed, signature, after)
    } else {
        // No quote found, append at the end
        format!("{}\r\n\r\n--\r\n{}", body, signature)
    }
}
