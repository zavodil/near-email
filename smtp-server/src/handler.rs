//! SMTP handler for near.email
//!
//! Parses incoming emails, extracts attachments, and stores them in the new JSON format.

use crate::{crypto, db};
use base64::{engine::general_purpose::STANDARD, Engine};
use mailin_embedded::{response, Handler, Response};
use mail_parser::{MessageParser, MimeHeaders};
use secp256k1::PublicKey;
use serde::Serialize;
use sqlx::PgPool;
use std::io;
use std::net::IpAddr;
use tokio::runtime::Handle;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Maximum email size in bytes (50MB)
const MAX_EMAIL_SIZE: usize = 50 * 1024 * 1024;

/// Attachment metadata for JSON format
#[derive(Debug, Serialize)]
struct AttachmentMeta {
    id: String,
    filename: String,
    content_type: String,
    size: usize,
}

/// Email content in outlayer-email format
#[derive(Debug, Serialize)]
struct EmailContent {
    format: &'static str,
    subject: String,
    body: String,
    attachments: Vec<AttachmentMeta>,
}

const EMAIL_FORMAT: &str = "outlayer-email";

/// SMTP handler that parses, encrypts and stores emails
#[derive(Clone)]
pub struct NearEmailHandler {
    db_pool: PgPool,
    master_pubkey: PublicKey,
    email_domain: String,
    default_account_suffix: String,
    rt_handle: Handle,
    db_api_url: String,
    api_secret: Option<String>,
    http_client: reqwest::Client,
    // Transaction state
    current_from: Option<String>,
    current_to: Vec<String>,
    current_data: Vec<u8>,
    size_exceeded: bool,
}

impl NearEmailHandler {
    pub fn new(
        db_pool: PgPool,
        master_pubkey: PublicKey,
        email_domain: String,
        default_account_suffix: String,
        rt_handle: Handle,
        db_api_url: String,
        api_secret: Option<String>,
    ) -> Self {
        Self {
            db_pool,
            master_pubkey,
            email_domain,
            default_account_suffix,
            rt_handle,
            db_api_url,
            api_secret,
            http_client: reqwest::Client::new(),
            current_from: None,
            current_to: Vec::new(),
            current_data: Vec::new(),
            size_exceeded: false,
        }
    }

    /// Extract NEAR account ID from email address
    fn extract_account_id(&self, email: &str) -> Option<String> {
        let email_lower = email.to_lowercase();
        let suffix = format!("@{}", self.email_domain);

        if email_lower.ends_with(&suffix) {
            let local_part = email_lower.strip_suffix(&suffix)?;
            if local_part.contains('.') {
                Some(local_part.to_string())
            } else {
                Some(format!("{}{}", local_part, self.default_account_suffix))
            }
        } else {
            None
        }
    }

    /// Process and store email for all recipients
    fn process_email(&self, from: &str, to: &[String], data: &[u8]) {
        // Parse email
        let parsed = match MessageParser::default().parse(data) {
            Some(msg) => msg,
            None => {
                error!("Failed to parse email from {}", from);
                return;
            }
        };

        // Extract subject
        let subject = parsed.subject().unwrap_or("").to_string();

        // Extract body (prefer text/plain, fallback to text/html)
        let body = parsed
            .body_text(0)
            .map(|s| s.to_string())
            .or_else(|| parsed.body_html(0).map(|s| s.to_string()))
            .unwrap_or_default();

        // Extract attachments
        let attachments: Vec<_> = parsed
            .attachments()
            .map(|att| {
                let filename = att
                    .attachment_name()
                    .unwrap_or("attachment")
                    .to_string();
                let content_type = att
                    .content_type()
                    .map(|ct| ct.c_type.to_string())
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                let data = att.contents().to_vec();
                (filename, content_type, data)
            })
            .collect();

        info!(
            "📧 Parsed email: from={}, subject_len={}, body_len={}, attachments={}",
            from,
            subject.len(),
            body.len(),
            attachments.len()
        );

        // Process for each recipient
        for recipient_email in to {
            let account_id = match self.extract_account_id(recipient_email) {
                Some(id) => id,
                None => {
                    warn!(
                        "Invalid recipient (not @{}): {}",
                        self.email_domain, recipient_email
                    );
                    continue;
                }
            };

            // Generate email_id upfront (needed for attachments)
            let email_id = Uuid::new_v4();

            // Store attachments and collect metadata
            let attachment_metas: Vec<AttachmentMeta> = self.rt_handle.block_on(async {
                let mut metas = Vec::new();

                for (filename, content_type, att_data) in &attachments {
                    // Encrypt attachment
                    let encrypted = match crypto::encrypt_for_account(
                        &self.master_pubkey,
                        &account_id,
                        att_data,
                    ) {
                        Ok(enc) => enc,
                        Err(e) => {
                            error!("Failed to encrypt attachment {}: {}", filename, e);
                            continue;
                        }
                    };

                    // Store via db-api
                    match self
                        .store_attachment(
                            &email_id,
                            &account_id,
                            filename,
                            content_type,
                            att_data.len(),
                            &encrypted,
                        )
                        .await
                    {
                        Ok(att_id) => {
                            metas.push(AttachmentMeta {
                                id: att_id,
                                filename: filename.to_string(),
                                content_type: content_type.to_string(),
                                size: att_data.len(),
                            });
                        }
                        Err(e) => {
                            error!("Failed to store attachment {}: {}", filename, e);
                        }
                    }
                }

                metas
            });

            // Create JSON content
            let content = EmailContent {
                format: EMAIL_FORMAT,
                subject: subject.clone(),
                body: body.clone(),
                attachments: attachment_metas,
            };

            let json_bytes = match serde_json::to_vec(&content) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to serialize email content: {}", e);
                    continue;
                }
            };

            // Encrypt JSON
            let encrypted =
                match crypto::encrypt_for_account(&self.master_pubkey, &account_id, &json_bytes) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Encryption failed for {}: {}", account_id, e);
                        continue;
                    }
                };

            // Store in database
            let db_pool = self.db_pool.clone();
            let from_clone = from.to_string();

            self.rt_handle.block_on(async {
                match db::store_email(&db_pool, &email_id, &account_id, &from_clone, &encrypted)
                    .await
                {
                    Ok(_) => {
                        info!(
                            "📧 Email {} stored: to={}, json={}B, encrypted={}B, attachments={}",
                            email_id,
                            account_id,
                            json_bytes.len(),
                            encrypted.len(),
                            content.attachments.len()
                        );
                    }
                    Err(e) => {
                        error!("Failed to store email for {}: {}", account_id, e);
                    }
                }
            });
        }
    }

    /// Store attachment via db-api HTTP call
    async fn store_attachment(
        &self,
        email_id: &Uuid,
        recipient: &str,
        filename: &str,
        content_type: &str,
        size: usize,
        encrypted_data: &[u8],
    ) -> Result<String, String> {
        let url = format!("{}/attachments", self.db_api_url);

        let body = serde_json::json!({
            "email_id": email_id.to_string(),
            "folder": "inbox",
            "recipient": recipient,
            "filename": filename,
            "content_type": content_type,
            "size": size as i32,
            "encrypted_data": STANDARD.encode(encrypted_data),
        });

        let mut request = self
            .http_client
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30));

        // Add API secret header if configured
        if let Some(secret) = &self.api_secret {
            request = request.header("X-API-Secret", secret);
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("db-api error {}: {}", status, text));
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        result["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "No id in response".to_string())
    }
}

impl Handler for NearEmailHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> Response {
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
        if self.size_exceeded {
            return Ok(());
        }

        if self.current_data.len() + buf.len() > MAX_EMAIL_SIZE {
            warn!(
                "Email exceeds size limit: {} + {} > {} bytes",
                self.current_data.len(),
                buf.len(),
                MAX_EMAIL_SIZE
            );
            self.size_exceeded = true;
            self.current_data.clear();
            return Ok(());
        }
        self.current_data.extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        if self.current_to.is_empty() {
            return response::NO_MAILBOX;
        }

        if self.size_exceeded {
            warn!(
                "Email rejected: message too large (> {} KB)",
                MAX_EMAIL_SIZE / 1024
            );
            return response::NO_MAILBOX;
        }

        let from = self.current_from.clone().unwrap_or_default();
        let recipients = std::mem::take(&mut self.current_to);
        let data = std::mem::take(&mut self.current_data);

        self.process_email(&from, &recipients, &data);

        response::OK
    }
}
