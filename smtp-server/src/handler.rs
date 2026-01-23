//! SMTP handler for near.email

use crate::{crypto, db};
use mailin_embedded::{response, Handler, Response};
use mail_parser::MessageParser;
use secp256k1::PublicKey;
use sqlx::PgPool;
use std::io;
use std::net::IpAddr;
use tokio::runtime::Handle;
use tracing::{error, info, warn};

/// Maximum email size in bytes (50MB)
/// Emails larger than this will be rejected
const MAX_EMAIL_SIZE: usize = 50 * 1024 * 1024;

/// SMTP handler that encrypts and stores emails
#[derive(Clone)]
pub struct NearEmailHandler {
    db_pool: PgPool,
    master_pubkey: PublicKey,
    email_domain: String,
    /// Default account suffix for simple addresses (e.g., ".near" or ".testnet")
    default_account_suffix: String,
    /// Tokio runtime handle for async operations (mailin runs in a separate thread pool)
    rt_handle: Handle,
    // Transaction state
    current_from: Option<String>,
    current_to: Vec<String>,
    current_data: Vec<u8>,
    /// Flag indicating message exceeded size limit
    size_exceeded: bool,
}

impl NearEmailHandler {
    pub fn new(
        db_pool: PgPool,
        master_pubkey: PublicKey,
        email_domain: String,
        default_account_suffix: String,
        rt_handle: Handle,
    ) -> Self {
        Self {
            db_pool,
            master_pubkey,
            email_domain,
            default_account_suffix,
            rt_handle,
            current_from: None,
            current_to: Vec::new(),
            current_data: Vec::new(),
            size_exceeded: false,
        }
    }

    /// Extract NEAR account ID from email address
    /// e.g., "vadim@near.email" -> "vadim.near" (mainnet) or "vadim.testnet" (testnet)
    /// e.g., "vadim.testnet@near.email" -> "vadim.testnet" (explicit)
    fn extract_account_id(&self, email: &str) -> Option<String> {
        let email_lower = email.to_lowercase();
        let suffix = format!("@{}", self.email_domain);

        if email_lower.ends_with(&suffix) {
            let local_part = email_lower.strip_suffix(&suffix)?;
            // Handle explicit subdomains: vadim.testnet@near.email -> vadim.testnet
            // Simple case: vadim@near.email -> vadim{default_suffix}
            if local_part.contains('.') {
                // Already has suffix like testnet/near, keep as is
                Some(local_part.to_string())
            } else {
                // Add default suffix (.near for mainnet, .testnet for testnet)
                Some(format!("{}{}", local_part, self.default_account_suffix))
            }
        } else {
            None
        }
    }

    /// Process and store email for all recipients
    fn process_email(&self, from: &str, to: &[String], data: &[u8]) {
        // Parse email to extract subject
        let subject_hint = MessageParser::default()
            .parse(data)
            .and_then(|msg| msg.subject().map(|s| s.to_string()));

        // Process each recipient
        for recipient_email in to {
            let account_id = match self.extract_account_id(recipient_email) {
                Some(id) => id,
                None => {
                    warn!("Invalid recipient (not @{}): {}", self.email_domain, recipient_email);
                    continue;
                }
            };

            // Encrypt email content for this account
            let encrypted = match crypto::encrypt_for_account(&self.master_pubkey, &account_id, data) {
                Ok(data) => data,
                Err(e) => {
                    error!("Encryption failed for {}: {}", account_id, e);
                    continue;
                }
            };

            // Store in database
            let db_pool = self.db_pool.clone();
            let account_id_clone = account_id.clone();
            let from_clone = from.to_string();
            let subject_clone = subject_hint.clone();

            // Calculate sizes for logging (without exposing content)
            let data_size = data.len();
            let encrypted_size = encrypted.len();

            // Run async database operation on the saved Tokio runtime handle
            // (mailin_embedded runs handlers in a separate thread pool without Tokio context)
            self.rt_handle.block_on(async {
                match db::store_email(
                    &db_pool,
                    &account_id_clone,
                    &from_clone,
                    subject_clone.as_deref(),
                    &encrypted,
                )
                .await
                {
                    Ok(id) => {
                        // Log only metadata, not content (privacy)
                        info!(
                            "📧 Email {} stored: to={}, raw={}B, encrypted={}B",
                            id, account_id_clone, data_size, encrypted_size
                        );
                    }
                    Err(e) => {
                        error!("Failed to store email for {}: {}", account_id_clone, e);
                    }
                }
            });
        }
    }
}

impl Handler for NearEmailHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> Response {
        // Reset state for new connection
        self.current_from = None;
        self.current_to.clear();
        self.current_data.clear();
        self.size_exceeded = false;
        response::OK
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> Response {
        self.current_from = Some(from.to_string());
        self.current_to.clear();
        self.current_data.clear();
        self.size_exceeded = false;
        response::OK
    }

    fn rcpt(&mut self, to: &str) -> Response {
        // Check if this is a valid @near.email address
        let suffix = format!("@{}", self.email_domain);
        if to.to_lowercase().ends_with(&suffix) {
            self.current_to.push(to.to_string());
            response::OK
        } else {
            warn!("Rejected recipient (not @{}): {}", self.email_domain, to);
            response::NO_MAILBOX
        }
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        self.current_data.clear();
        response::OK
    }

    fn data(&mut self, buf: &[u8]) -> io::Result<()> {
        // Skip if already exceeded size limit
        if self.size_exceeded {
            return Ok(());
        }

        // Check size limit before accepting more data
        if self.current_data.len() + buf.len() > MAX_EMAIL_SIZE {
            warn!(
                "Email exceeds size limit: {} + {} > {} bytes",
                self.current_data.len(),
                buf.len(),
                MAX_EMAIL_SIZE
            );
            self.size_exceeded = true;
            self.current_data.clear();
            return Ok(()); // Accept data but mark as exceeded
        }
        self.current_data.extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        if self.current_to.is_empty() {
            return response::NO_MAILBOX;
        }

        // Check if size limit was exceeded
        if self.size_exceeded {
            warn!("Email rejected: message too large (> {} KB)", MAX_EMAIL_SIZE / 1024);
            return response::NO_MAILBOX; // Use NO_MAILBOX as fallback (552 not available)
        }

        let from = self.current_from.clone().unwrap_or_default();
        let recipients = std::mem::take(&mut self.current_to);
        let data = std::mem::take(&mut self.current_data);

        // Store email with attachments as-is
        self.process_email(&from, &recipients, &data);

        response::OK
    }
}
