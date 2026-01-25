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
mod http_chunked;
#[allow(dead_code)]
mod near; // Keep for potential future use
mod types;

use libsecp256k1::SecretKey;
use outlayer::{env, storage};
use types::*;

// ==================== Hardcoded Config ====================
// These values are constant and don't need to be in secrets

/// Database API URL (internal service)
const DATABASE_API_URL: &str = "https://mail.near.email";

/// Email signature template (use %account% for sender's NEAR account)
const EMAIL_SIGNATURE: Option<&str> = Some("Sent onchain by %account% via OutLayer");

/// Storage key for master key in worker-encrypted storage
const MASTER_KEY_STORAGE_KEY: &str = "master_key";

// ==================== Config Functions ====================

/// Get account suffix based on network (.near for mainnet, .testnet for testnet)
/// Uses NEAR_NETWORK_ID env var injected by coordinator
fn get_account_suffix() -> &'static str {
    match std::env::var("NEAR_NETWORK_ID").as_deref() {
        Ok("testnet") => ".testnet",
        _ => ".near" // default to mainnet
    }
}

/// Get master private key from env (secrets) or storage
/// Priority: env (secrets, if running with secrets) > worker storage (after migration)
fn get_master_key() -> Result<SecretKey, Box<dyn std::error::Error>> {
    // 1. If PROTECTED_MASTER_KEY is in env (running with secrets), use it
    if let Ok(key_hex) = std::env::var("PROTECTED_MASTER_KEY") {
        return crypto::parse_private_key(&key_hex);
    }

    // 2. Otherwise read from worker storage (after migration)
    if let Some(key_bytes) = storage::get_worker(MASTER_KEY_STORAGE_KEY)? {
        let key_hex = String::from_utf8(key_bytes)
            .map_err(|e| format!("Invalid master key encoding in storage: {}", e))?;
        return crypto::parse_private_key(&key_hex);
    }

    // 3. Not found
    Err("Master key not configured. Run migrate_master_key action or enable secrets.".into())
}

/// Handle migrate_master_key action
/// Migrates master key from env (secrets) to worker-encrypted storage
/// Only works if:
/// 1. PROTECTED_MASTER_KEY exists in env (via secrets)
/// 2. Key is NOT already in storage (prevents overwrite)
fn handle_migrate_master_key() -> Result<Response, Box<dyn std::error::Error>> {
    // 1. Check that key exists in env (must be running with secrets)
    let key_from_env = std::env::var("PROTECTED_MASTER_KEY")
        .map_err(|_| "PROTECTED_MASTER_KEY not found in env. Run with secrets enabled.")?;

    // 2. Check that key is NOT already in storage (prevent overwrite)
    let storage_key = format!("@worker:{}", MASTER_KEY_STORAGE_KEY);
    if storage::has(&storage_key) {
        return Err("Master key already exists in storage. Migration not needed.".into());
    }

    // 3. Validate the key
    let privkey = crypto::parse_private_key(&key_from_env)?;

    // 4. Save to worker storage (encrypted by OutLayer)
    storage::set_worker(MASTER_KEY_STORAGE_KEY, key_from_env.as_bytes())?;

    // 5. Return public key for verification
    let pubkey = crypto::get_master_pubkey(&privkey);

    Ok(Response::MigrateMasterKey(MigrateMasterKeyResponse {
        success: true,
        pubkey,
        message: "Master key migrated to worker storage. Future runs don't need secrets.".to_string(),
    }))
}

fn main() {
    // Force storage interface import by actually calling it (required for project context)
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
    // Read raw input
    let raw_input = env::input();
    let raw_str = String::from_utf8_lossy(&raw_input);

    // Parse input
    let input: Request = serde_json::from_slice(&raw_input)
        .map_err(|e| format!("Failed to parse input: {}. Raw: {}", e, raw_str))?;

    // Handle MigrateMasterKey before getting master key (it needs special logic)
    if matches!(input, Request::MigrateMasterKey) {
        return handle_migrate_master_key();
    }

    // Get master private key from storage or env
    let master_privkey = get_master_key()?;

    // Use hardcoded database API URL
    let db_api_url = DATABASE_API_URL;

    // Get account suffix based on network
    let default_account_suffix = get_account_suffix();

    // Use hardcoded email signature
    let email_signature = EMAIL_SIGNATURE;

    // Get authenticated signer from OutLayer
    let get_signer = || -> Result<String, Box<dyn std::error::Error>> {
        env::signer_account_id()
            .ok_or_else(|| "No signer account - must be called via NEAR transaction".into())
    };

    match input {
        Request::GetEmails {
            ephemeral_pubkey,
            max_output_size,
            inbox_offset,
            sent_offset,
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            let account_id = get_signer()?;
            let max_size = max_output_size.unwrap_or(DEFAULT_MAX_OUTPUT_SIZE);
            let ephemeral_pubkey_bytes = hex::decode(&ephemeral_pubkey)
                .map_err(|e| format!("Invalid ephemeral_pubkey hex: {}", e))?;

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Fetch and decrypt emails with size limit
            let (email_data, inbox_next, sent_next) = fetch_combined_emails(
                db_api_url,
                &account_id,
                &user_privkey,
                max_size,
                inbox_offset.unwrap_or(0),
                sent_offset.unwrap_or(0),
            )?;

            // Serialize and encrypt
            let data_json = serde_json::to_vec(&email_data)?;
            let encrypted = ecies::encrypt(&ephemeral_pubkey_bytes, &data_json)
                .map_err(|e| format!("Failed to encrypt response: {}", e))?;

            // Get signer's public key for encrypting outgoing emails
            let send_pubkey = crypto::derive_user_pubkey(&master_privkey, &account_id)?;

            Ok(Response::GetEmails(GetEmailsResponse {
                success: true,
                encrypted_data: STANDARD.encode(&encrypted),
                send_pubkey: hex::encode(&send_pubkey),
                inbox_next_offset: inbox_next,
                sent_next_offset: sent_next,
            }))
        }

        Request::SendEmail {
            encrypted_data,
            ephemeral_pubkey,
            max_output_size: _, // Not used - we return empty EmailData, frontend refreshes separately
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            eprintln!("[DEBUG] SendEmail: start, encrypted_data len={}", encrypted_data.len());

            let account_id = get_signer()?;
            eprintln!("[DEBUG] SendEmail: account_id={}", account_id);

            let ephemeral_pubkey_bytes = hex::decode(&ephemeral_pubkey)
                .map_err(|e| format!("Invalid ephemeral_pubkey hex: {}", e))?;

            // Validate sender account
            validate_sender_account(&account_id, default_account_suffix)?;
            eprintln!("[DEBUG] SendEmail: validated sender");

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;
            eprintln!("[DEBUG] SendEmail: derived privkey");

            // Decrypt the combined payload (to, subject, body, attachments)
            eprintln!("[DEBUG] SendEmail: decoding base64...");
            let ciphertext = STANDARD.decode(&encrypted_data)
                .map_err(|e| format!("Invalid encrypted_data base64: {}", e))?;
            eprintln!("[DEBUG] SendEmail: ciphertext len={}", ciphertext.len());

            eprintln!("[DEBUG] SendEmail: decrypting EC01...");
            let decrypted_bytes = crypto::decrypt_email(&user_privkey, &ciphertext)?;
            eprintln!("[DEBUG] SendEmail: decrypted, len={}", decrypted_bytes.len());

            let decrypted_json = String::from_utf8(decrypted_bytes)
                .map_err(|e| format!("Invalid UTF-8 in encrypted_data: {}", e))?;
            eprintln!("[DEBUG] SendEmail: parsed UTF-8");

            let payload: SendEmailPayload = serde_json::from_str(&decrypted_json)
                .map_err(|e| format!("Invalid SendEmailPayload JSON: {}", e))?;
            eprintln!("[DEBUG] SendEmail: parsed JSON, attachments count={}", payload.attachments.len());

            let to = payload.to;
            let subject = payload.subject;
            let body = payload.body;
            let attachments = payload.attachments;

            // Check if internal email (@near.email)
            let internal_suffix = "@near.email";
            let tx_hash = env::transaction_hash();

            // Build sender email address
            let sender_local = account_id
                .strip_suffix(default_account_suffix)
                .unwrap_or(&account_id);
            let sender_email = format!("{}@near.email", sender_local);

            // Add signature if configured
            let body_with_sig = if let Some(sig_template) = email_signature {
                let signature = sig_template.replace("%account%", &account_id);
                insert_signature_before_quote(&body, &signature)
            } else {
                body.clone()
            };

            eprintln!("[DEBUG] SendEmail: building email content...");
            // Build email content (with or without attachments) - MIME format for actual sending
            let email_content = build_email_content(
                &sender_email,
                &to,
                &subject,
                &body_with_sig,
                &attachments,
            );
            eprintln!("[DEBUG] SendEmail: email_content len={}", email_content.len());

            // Generate UUID for sent email (needed before storing attachments)
            let sent_email_id = uuid::Uuid::new_v4().to_string();
            eprintln!("[DEBUG] SendEmail: generated sent_email_id={}", sent_email_id);

            // Build sent folder content with lazy attachments (stores large attachments separately)
            eprintln!("[DEBUG] SendEmail: building sent email with lazy attachments...");
            let sent_result = build_sent_email_with_lazy_attachments(
                db_api_url,
                &sent_email_id,
                &account_id,
                &master_privkey,
                &sender_email,
                &to,
                &subject,
                &body_with_sig,
                &attachments,
            )?;
            eprintln!("[DEBUG] SendEmail: sent_content len={}", sent_result.json_content.len());

            // Encrypt sent content for sender's sent folder
            eprintln!("[DEBUG] SendEmail: encrypting for sender...");
            let encrypted_for_sender = crypto::encrypt_for_account(
                &master_privkey,
                &account_id,
                sent_result.json_content.as_bytes(),
            )?;
            eprintln!("[DEBUG] SendEmail: encrypted_for_sender len={}", encrypted_for_sender.len());

            let message_id = if to.to_lowercase().ends_with(internal_suffix) {
                // Internal email - encrypt and store directly
                let recipient_account = extract_account_from_email(&to, internal_suffix, default_account_suffix);
                eprintln!("[DEBUG] SendEmail: internal email to {}", recipient_account);

                eprintln!("[DEBUG] SendEmail: encrypting for recipient...");
                let encrypted = crypto::encrypt_for_account(
                    &master_privkey,
                    &recipient_account,
                    email_content.as_bytes(),
                )?;
                eprintln!("[DEBUG] SendEmail: encrypted len={}", encrypted.len());

                eprintln!("[DEBUG] SendEmail: storing internal email...");
                let email_id = db::store_internal_email(
                    db_api_url,
                    &recipient_account,
                    &sender_email,
                    &encrypted,
                )?;
                eprintln!("[DEBUG] SendEmail: stored, email_id={}", email_id);

                // Store in sender's sent folder with pre-generated ID
                eprintln!("[DEBUG] SendEmail: storing sent email...");
                let _ = db::store_sent_email(
                    db_api_url,
                    &account_id,
                    &to,
                    &encrypted_for_sender,
                    tx_hash.as_deref(),
                    Some(&sent_email_id),
                );
                eprintln!("[DEBUG] SendEmail: stored sent");

                Some(email_id)
            } else {
                // External email - send via SMTP relay with attachments
                eprintln!("[DEBUG] SendEmail: external email to {}", to);
                eprintln!("[DEBUG] SendEmail: calling db::send_email_with_attachments...");
                db::send_email_with_attachments(
                    db_api_url,
                    &account_id,
                    &to,
                    &subject,
                    &body_with_sig,
                    &attachments,
                )?;
                eprintln!("[DEBUG] SendEmail: sent external email");

                // Store in sender's sent folder with pre-generated ID
                eprintln!("[DEBUG] SendEmail: storing sent email...");
                let _ = db::store_sent_email(
                    db_api_url,
                    &account_id,
                    &to,
                    &encrypted_for_sender,
                    tx_hash.as_deref(),
                    Some(&sent_email_id),
                );
                eprintln!("[DEBUG] SendEmail: stored sent");

                None
            };

            // Fetch all emails (inbox + sent) with lazy loading
            // Now that sent emails use lazy attachments, response should be within size limit
            let max_size = DEFAULT_MAX_OUTPUT_SIZE;
            let (mut email_data, _, _) = fetch_combined_emails(
                db_api_url,
                &account_id,
                &user_privkey,
                max_size,
                0,
                0,
            )?;

            // Check if just-sent email is already in the fetched results
            // (might not be due to timing - we just stored it)
            let sent_email_exists = email_data.sent.iter().any(|e| e.id == sent_email_id);
            if !sent_email_exists {
                // Add the just-sent email to the beginning of sent list
                let sent_email = SentEmail {
                    id: sent_email_id.clone(),
                    to: to.clone(),
                    subject: subject.clone(),
                    body: body_with_sig.clone(),
                    tx_hash: tx_hash.clone(),
                    sent_at: get_current_timestamp(),
                    attachments: sent_result.attachments,
                };
                email_data.sent.insert(0, sent_email);
            }

            let data_json = serde_json::to_vec(&email_data)?;
            let encrypted = ecies::encrypt(&ephemeral_pubkey_bytes, &data_json)
                .map_err(|e| format!("Failed to encrypt response: {}", e))?;

            eprintln!("[DEBUG] SendEmail: returning success response with all emails");

            Ok(Response::SendEmail(SendEmailResponse {
                success: true,
                message_id,
                encrypted_data: STANDARD.encode(&encrypted),
            }))
        }

        Request::DeleteEmail {
            email_id,
            ephemeral_pubkey,
            max_output_size,
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            let account_id = get_signer()?;
            let max_size = max_output_size.unwrap_or(DEFAULT_MAX_OUTPUT_SIZE);
            let ephemeral_pubkey_bytes = hex::decode(&ephemeral_pubkey)
                .map_err(|e| format!("Invalid ephemeral_pubkey hex: {}", e))?;

            // Delete email from database
            let deleted = db::delete_email(db_api_url, &email_id, &account_id)?;

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Fetch fresh inbox/sent preview after deleting
            let (email_data, _, _) = fetch_combined_emails(
                db_api_url,
                &account_id,
                &user_privkey,
                max_size,
                0,
                0,
            )?;

            let data_json = serde_json::to_vec(&email_data)?;
            let encrypted = ecies::encrypt(&ephemeral_pubkey_bytes, &data_json)
                .map_err(|e| format!("Failed to encrypt response: {}", e))?;

            Ok(Response::DeleteEmail(DeleteEmailResponse {
                success: true,
                deleted,
                encrypted_data: STANDARD.encode(&encrypted),
            }))
        }

        Request::GetEmailCount => {
            let account_id = get_signer()?;

            let inbox_count = db::count_emails(db_api_url, &account_id)?;
            let sent_count = db::count_sent_emails(db_api_url, &account_id)?;

            Ok(Response::GetEmailCount(GetEmailCountResponse {
                success: true,
                inbox_count,
                sent_count,
            }))
        }

        Request::GetMasterPublicKey => {
            let pubkey_hex = crypto::get_master_pubkey(&master_privkey);

            Ok(Response::GetMasterPublicKey(GetMasterPublicKeyResponse {
                success: true,
                public_key: pubkey_hex,
            }))
        }

        Request::GetAttachment {
            attachment_id,
            ephemeral_pubkey,
        } => {
            use base64::{engine::general_purpose::STANDARD, Engine};

            let account_id = get_signer()?;
            let ephemeral_pubkey_bytes = hex::decode(&ephemeral_pubkey)
                .map_err(|e| format!("Invalid ephemeral_pubkey hex: {}", e))?;

            // Derive user's private key for decryption
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Fetch encrypted attachment from database
            let attachment = db::fetch_attachment(
                db_api_url,
                &attachment_id,
                &account_id,
            )?;

            // Decrypt attachment data
            let decrypted = crypto::decrypt_email(&user_privkey, &attachment.encrypted_data)?;

            // Re-encrypt with ephemeral key for response
            let encrypted = ecies::encrypt(&ephemeral_pubkey_bytes, &decrypted)
                .map_err(|e| format!("Failed to encrypt attachment: {}", e))?;

            Ok(Response::GetAttachment(GetAttachmentResponse {
                success: true,
                encrypted_data: STANDARD.encode(&encrypted),
                filename: attachment.filename,
                content_type: attachment.content_type,
                size: attachment.size as usize,
            }))
        }

        // Already handled at the beginning of process()
        Request::MigrateMasterKey => unreachable!(),
    }
}

/// Fetch combined inbox + sent emails with size limit
/// Returns (EmailData, inbox_next_offset, sent_next_offset)
/// Attachments are lazy-loaded by ID (stored by SMTP server)
fn fetch_combined_emails(
    api_url: &str,
    account_id: &str,
    user_privkey: &libsecp256k1::SecretKey,
    max_size: usize,
    inbox_offset: i64,
    sent_offset: i64,
) -> Result<(EmailData, Option<i64>, Option<i64>), Box<dyn std::error::Error>> {
    // Reserve some space for JSON overhead and encryption
    let effective_max = max_size.saturating_sub(10_000);
    let mut current_size: usize = 0;

    // Fetch inbox emails
    let encrypted_inbox = db::fetch_emails(api_url, account_id, 100, inbox_offset)?;
    let mut inbox_emails = Vec::new();
    let mut inbox_next: Option<i64> = None;

    for (idx, enc_email) in encrypted_inbox.into_iter().enumerate() {
        match crypto::decrypt_email(user_privkey, &enc_email.encrypted_data) {
            Ok(decrypted) => {
                let parsed = parse_email(&decrypted)?;

                // Attachments are already processed by SMTP, just use them directly
                let attachments = parsed.attachments;

                // Calculate email size (all attachments are lazy, only metadata counts)
                let attachments_size: usize = attachments.iter()
                    .map(|a| {
                        let base = a.filename.len() + a.content_type.len() + 50;
                        if let Some(ref data) = a.data {
                            base + data.len()
                        } else {
                            base + 50  // Just metadata for lazy attachments
                        }
                    })
                    .sum();

                let full_email_size = enc_email.id.len() + enc_email.sender_email.len() +
                    parsed.subject.len() + parsed.body.len() + enc_email.received_at.len() +
                    attachments_size + 100;

                // Size of a truncated email (without body content and attachments)
                let truncated_size = enc_email.id.len() + enc_email.sender_email.len() +
                    parsed.subject.len() + 100 + enc_email.received_at.len() + 100;

                if current_size + full_email_size <= effective_max {
                    // Full email fits
                    let email = Email {
                        id: enc_email.id,
                        from: enc_email.sender_email,
                        subject: parsed.subject,
                        body: parsed.body,
                        received_at: enc_email.received_at,
                        attachments,
                    };
                    current_size += full_email_size;
                    inbox_emails.push(email);
                } else if current_size + truncated_size <= effective_max {
                    // Email too large, show truncated version
                    let att_count = attachments.len();
                    let att_info = if att_count > 0 {
                        format!("\n\n[{} attachment(s) not shown]", att_count)
                    } else {
                        String::new()
                    };

                    let email = Email {
                        id: enc_email.id,
                        from: enc_email.sender_email,
                        subject: parsed.subject,
                        body: format!("[Email too large to display in this view]{}", att_info),
                        received_at: enc_email.received_at,
                        attachments: Vec::new(),
                    };
                    current_size += truncated_size;
                    inbox_emails.push(email);
                } else {
                    // Can't fit even truncated version, stop here
                    inbox_next = Some(inbox_offset + idx as i64);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to decrypt inbox email {}: {}", enc_email.id, e);
            }
        }
    }

    // Check if there are more inbox emails
    if inbox_next.is_none() && inbox_emails.len() == 100 {
        // Fetched max limit, there might be more
        inbox_next = Some(inbox_offset + 100);
    }

    // Fetch sent emails (if still under size limit)
    let encrypted_sent = db::fetch_sent_emails(api_url, account_id, 100, sent_offset)?;
    let mut sent_emails = Vec::new();
    let mut sent_next: Option<i64> = None;

    for (idx, enc_email) in encrypted_sent.into_iter().enumerate() {
        match crypto::decrypt_email(user_privkey, &enc_email.encrypted_data) {
            Ok(decrypted) => {
                let parsed = parse_email(&decrypted)?;

                // Attachments are already processed, just use them directly
                let attachments = parsed.attachments;

                // Calculate email size (all attachments are lazy, only metadata counts)
                let attachments_size: usize = attachments.iter()
                    .map(|a| {
                        let base = a.filename.len() + a.content_type.len() + 50;
                        if let Some(ref data) = a.data {
                            base + data.len()
                        } else {
                            base + 50  // Just metadata for lazy attachments
                        }
                    })
                    .sum();

                let full_email_size = enc_email.id.len() + enc_email.recipient_email.len() +
                    parsed.subject.len() + parsed.body.len() + enc_email.sent_at.len() +
                    attachments_size + 100;

                let truncated_size = enc_email.id.len() + enc_email.recipient_email.len() +
                    parsed.subject.len() + 100 + enc_email.sent_at.len() + 100;

                if current_size + full_email_size <= effective_max {
                    // Full email fits
                    let email = SentEmail {
                        id: enc_email.id,
                        to: enc_email.recipient_email,
                        subject: parsed.subject,
                        body: parsed.body,
                        tx_hash: enc_email.tx_hash,
                        sent_at: enc_email.sent_at,
                        attachments,
                    };
                    current_size += full_email_size;
                    sent_emails.push(email);
                } else if current_size + truncated_size <= effective_max {
                    // Email too large, show truncated version
                    let att_count = attachments.len();
                    let att_info = if att_count > 0 {
                        format!("\n\n[{} attachment(s) not shown]", att_count)
                    } else {
                        String::new()
                    };

                    let email = SentEmail {
                        id: enc_email.id,
                        to: enc_email.recipient_email,
                        subject: parsed.subject,
                        body: format!("[Email too large to display in this view]{}", att_info),
                        tx_hash: enc_email.tx_hash,
                        sent_at: enc_email.sent_at,
                        attachments: Vec::new(),
                    };
                    current_size += truncated_size;
                    sent_emails.push(email);
                } else {
                    // Can't fit even truncated version, stop here
                    sent_next = Some(sent_offset + idx as i64);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to decrypt sent email {}: {}", enc_email.id, e);
            }
        }
    }

    // Check if there are more sent emails
    if sent_next.is_none() && sent_emails.len() == 100 {
        sent_next = Some(sent_offset + 100);
    }

    Ok((
        EmailData {
            inbox: inbox_emails,
            sent: sent_emails,
        },
        inbox_next,
        sent_next,
    ))
}

/// JSON format for emails (outlayer-email)
#[derive(Debug, serde::Deserialize)]
struct EmailJson {
    format: String,
    subject: String,
    body: String,
    #[serde(default)]
    attachments: Vec<AttachmentJson>,
}

#[derive(Debug, serde::Deserialize)]
struct AttachmentJson {
    id: String,
    filename: String,
    content_type: String,
    size: usize,
}

/// Parse decrypted email content (outlayer-email format)
fn parse_email(data: &[u8]) -> Result<ParsedEmail, Box<dyn std::error::Error>> {
    let json: EmailJson = serde_json::from_slice(data)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    if json.format != "outlayer-email" {
        return Err(format!("Unknown format: {} (expected outlayer-email)", json.format).into());
    }

    let attachments = json.attachments.into_iter().map(|att| types::Attachment {
        filename: att.filename,
        content_type: att.content_type,
        data: None,
        size: att.size,
        attachment_id: Some(att.id),
    }).collect();

    Ok(ParsedEmail {
        subject: json.subject,
        body: json.body,
        attachments,
    })
}

/// Result of building sent email content with lazy attachments
struct SentEmailContent {
    /// JSON string to be encrypted and stored
    json_content: String,
    /// Processed attachments with lazy loading info (for immediate response)
    attachments: Vec<types::Attachment>,
}

/// Build sent email content with lazy attachment support
///
/// Large attachments (>= ATTACHMENT_LAZY_THRESHOLD) are stored separately
/// and only referenced in the email content. This prevents large encrypted
/// blobs in the sent_emails table.
///
/// Returns both the JSON content for storage and the processed attachments for response.
fn build_sent_email_with_lazy_attachments(
    api_url: &str,
    email_id: &str,
    account_id: &str,
    master_privkey: &libsecp256k1::SecretKey,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    attachments: &[Attachment],
) -> Result<SentEmailContent, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use types::ATTACHMENT_LAZY_THRESHOLD;

    let mut json_attachments = Vec::new();
    let mut result_attachments = Vec::new();

    for att in attachments {
        let data_bytes = match &att.data {
            Some(b64) => STANDARD.decode(b64)?,
            None => continue,
        };

        if data_bytes.len() < ATTACHMENT_LAZY_THRESHOLD {
            // Small attachment - include inline
            json_attachments.push(serde_json::json!({
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "data": att.data,
                "attachment_id": null
            }));
            result_attachments.push(types::Attachment {
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                data: att.data.clone(),
                size: att.size,
                attachment_id: None,
            });
        } else {
            // Large attachment - store separately for lazy loading
            let encrypted = crypto::encrypt_for_account(master_privkey, account_id, &data_bytes)?;

            let attachment_id = db::store_attachment(
                api_url,
                email_id,
                "sent",
                account_id,
                &att.filename,
                &att.content_type,
                att.size,
                &encrypted,
            )?;

            json_attachments.push(serde_json::json!({
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "data": null,
                "attachment_id": attachment_id
            }));
            result_attachments.push(types::Attachment {
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                data: None, // Lazy - no inline data
                size: att.size,
                attachment_id: Some(attachment_id),
            });
        }
    }

    let email_json = serde_json::json!({
        "format": "outlayer-email",
        "subject": subject,
        "body": body,
        "attachments": json_attachments
    });

    Ok(SentEmailContent {
        json_content: email_json.to_string(),
        attachments: result_attachments,
    })
}

struct ParsedEmail {
    subject: String,
    body: String,
    attachments: Vec<types::Attachment>,
}

/// Validate that account_id is allowed to send emails
fn validate_sender_account(account_id: &str, expected_suffix: &str) -> Result<(), Box<dyn std::error::Error>> {
    if account_id.len() == 64 && account_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Implicit accounts cannot send emails. Please use a named account ending with {}",
            expected_suffix
        ).into());
    }

    if !account_id.ends_with(expected_suffix) {
        return Err(format!(
            "Account '{}' cannot send emails. Only accounts ending with '{}' are supported.",
            account_id, expected_suffix
        ).into());
    }

    Ok(())
}

/// Extract NEAR account ID from email address
fn extract_account_from_email(email: &str, email_suffix: &str, default_account_suffix: &str) -> String {
    let email_lower = email.to_lowercase();
    let local_part = email_lower
        .strip_suffix(email_suffix)
        .unwrap_or(&email_lower)
        .to_string();

    if local_part.contains('.') {
        local_part
    } else {
        format!("{}{}", local_part, default_account_suffix)
    }
}

/// Build email content with optional attachments (MIME multipart if needed)
fn build_email_content(
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    attachments: &[Attachment],
) -> String {
    if attachments.is_empty() {
        // Simple text email
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
            from, to, subject, body
        )
    } else {
        // MIME multipart email with attachments
        let boundary = format!("----=_Part_{:016x}", rand_u64());

        let mut result = String::new();
        result.push_str(&format!("From: {}\r\n", from));
        result.push_str(&format!("To: {}\r\n", to));
        result.push_str(&format!("Subject: {}\r\n", subject));
        result.push_str("MIME-Version: 1.0\r\n");
        result.push_str(&format!("Content-Type: multipart/mixed; boundary=\"{}\"\r\n", boundary));
        result.push_str("\r\n");

        // Body part
        result.push_str(&format!("--{}\r\n", boundary));
        result.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        result.push_str("Content-Transfer-Encoding: 8bit\r\n");
        result.push_str("\r\n");
        result.push_str(body);
        result.push_str("\r\n");

        // Attachment parts
        for att in attachments {
            // For sending, attachments must have inline data
            let data = match &att.data {
                Some(d) => d,
                None => continue,  // Skip attachments without data (shouldn't happen for sending)
            };

            result.push_str(&format!("--{}\r\n", boundary));
            result.push_str(&format!("Content-Type: {}; name=\"{}\"\r\n", att.content_type, att.filename));
            result.push_str("Content-Transfer-Encoding: base64\r\n");
            result.push_str(&format!("Content-Disposition: attachment; filename=\"{}\"\r\n", att.filename));
            result.push_str("\r\n");
            // Split base64 into 76-char lines
            for chunk in data.as_bytes().chunks(76) {
                result.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                result.push_str("\r\n");
            }
        }

        // End boundary
        result.push_str(&format!("--{}--\r\n", boundary));

        result
    }
}

/// Simple pseudo-random u64 for boundary generation
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_nanos() as u64 ^ 0xDEADBEEF
}

/// Get current timestamp in ISO 8601 format
fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Convert to date/time components (simplified UTC)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let mut y = 1970;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let days_in_months = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 1;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        m += 1;
    }
    let d = remaining_days + 1;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, minutes, seconds)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Insert signature before quoted text markers
fn insert_signature_before_quote(body: &str, signature: &str) -> String {
    let quote_markers = [
        "-------- Original Message --------",
        "---------- Forwarded message ---------",
    ];

    let mut earliest_pos: Option<usize> = None;

    for marker in &quote_markers {
        if let Some(pos) = body.find(marker) {
            earliest_pos = Some(earliest_pos.map_or(pos, |e| e.min(pos)));
        }
    }

    if let Some(on_pos) = body.find("\nOn ") {
        let after_on = &body[on_pos..];
        if after_on.contains("wrote:") || after_on.contains("написал:") {
            earliest_pos = Some(earliest_pos.map_or(on_pos, |e| e.min(on_pos)));
        }
    }

    if let Some(pos) = earliest_pos {
        let (before, after) = body.split_at(pos);
        let before_trimmed = before.trim_end();
        format!("{}\r\n\r\n--\r\n{}\r\n\r\n{}", before_trimmed, signature, after)
    } else {
        format!("{}\r\n\r\n--\r\n{}", body, signature)
    }
}
