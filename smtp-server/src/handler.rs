//! SMTP handler for near.email

use crate::{crypto, db};
use mailin_embedded::{Handler, Response};
use mail_parser::MessageParser;
use secp256k1::PublicKey;
use sqlx::PgPool;
use std::net::IpAddr;
use tracing::{error, info, warn};

/// SMTP handler that encrypts and stores emails
pub struct NearEmailHandler {
    db_pool: PgPool,
    master_pubkey: PublicKey,
    email_domain: String,
    // Transaction state
    current_from: Option<String>,
    current_to: Vec<String>,
}

impl NearEmailHandler {
    pub fn new(db_pool: PgPool, master_pubkey: PublicKey, email_domain: String) -> Self {
        Self {
            db_pool,
            master_pubkey,
            email_domain,
            current_from: None,
            current_to: Vec::new(),
        }
    }

    /// Extract NEAR account ID from email address
    /// e.g., "vadim@near.email" -> "vadim.near"
    fn extract_account_id(&self, email: &str) -> Option<String> {
        let email_lower = email.to_lowercase();
        let suffix = format!("@{}", self.email_domain);

        if email_lower.ends_with(&suffix) {
            let local_part = email_lower.strip_suffix(&suffix)?;
            // Handle subdomains: vadim.testnet@near.email -> vadim.testnet
            // Simple case: vadim@near.email -> vadim.near
            if local_part.contains('.') {
                // Already has suffix like testnet, keep as is
                Some(local_part.to_string())
            } else {
                // Add .near suffix
                Some(format!("{}.near", local_part))
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

            // Use blocking task for async database operation
            tokio::task::block_in_place(|| {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
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
                            info!(
                                "Stored email {} for {} from {} (subject: {:?})",
                                id, account_id_clone, from_clone, subject_clone
                            );
                        }
                        Err(e) => {
                            error!("Failed to store email for {}: {}", account_id_clone, e);
                        }
                    }
                });
            });
        }
    }
}

impl Handler for NearEmailHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> Response {
        // Reset state for new connection
        self.current_from = None;
        self.current_to.clear();
        Response::Ok
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> Response {
        self.current_from = Some(from.to_string());
        self.current_to.clear();
        Response::Ok
    }

    fn rcpt(&mut self, to: &str) -> Response {
        // Check if this is a valid @near.email address
        let suffix = format!("@{}", self.email_domain);
        if to.to_lowercase().ends_with(&suffix) {
            self.current_to.push(to.to_string());
            Response::Ok
        } else {
            warn!("Rejected recipient (not @{}): {}", self.email_domain, to);
            Response::NoMailbox
        }
    }

    fn data(&mut self, _domain: &str, from: &str, _is8bit: bool, data: &[u8]) -> Response {
        if self.current_to.is_empty() {
            return Response::NoMailbox;
        }

        let recipients = std::mem::take(&mut self.current_to);
        self.process_email(from, &recipients, data);

        Response::Ok
    }
}
