//! Request/Response types for near.email WASI module

use serde::{Deserialize, Deserializer, Serialize};

/// Default max output size: 1.5 MB
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 1_500_000;

/// Deserialize base64-encoded string as Vec<u8>
fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use base64::{engine::general_purpose::STANDARD, Engine};
    let s: String = Deserialize::deserialize(deserializer)?;
    STANDARD.decode(&s).map_err(serde::de::Error::custom)
}

// ==================== Request Types ====================

#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Get emails (inbox + sent) for the signer
    /// Response is encrypted with ephemeral_pubkey for client-side decryption
    /// Returns as many emails as fit within max_output_size
    GetEmails {
        /// Client's ephemeral secp256k1 public key (hex, 33 bytes compressed)
        ephemeral_pubkey: String,
        /// Max output size in bytes (default: 1.5MB)
        #[serde(default)]
        max_output_size: Option<usize>,
        /// Offset for inbox emails
        #[serde(default)]
        inbox_offset: Option<i64>,
        /// Offset for sent emails
        #[serde(default)]
        sent_offset: Option<i64>,
    },

    /// Send email from the signer's account
    /// Returns fresh inbox/sent preview after sending
    SendEmail {
        to: String,
        /// Base64-encoded ECIES ciphertext of subject
        encrypted_subject: String,
        /// Base64-encoded ECIES ciphertext of body
        encrypted_body: String,
        /// Base64-encoded ECIES ciphertext of attachments JSON (array of {filename, content_type, data_base64})
        #[serde(default)]
        encrypted_attachments: Option<String>,
        /// Client's ephemeral public key for encrypting response
        ephemeral_pubkey: String,
        /// Max output size in bytes (default: 1.5MB)
        #[serde(default)]
        max_output_size: Option<usize>,
    },

    /// Delete an email (must belong to signer)
    /// Returns fresh inbox/sent preview after deleting
    DeleteEmail {
        email_id: String,
        /// Client's ephemeral public key for encrypting response
        ephemeral_pubkey: String,
        /// Max output size in bytes (default: 1.5MB)
        #[serde(default)]
        max_output_size: Option<usize>,
    },

    /// Get email count for the signer
    GetEmailCount,

    /// Get master public key (for SMTP server encryption)
    GetMasterPublicKey,
}

// ==================== Response Types ====================

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    GetEmails(GetEmailsResponse),
    SendEmail(SendEmailResponse),
    DeleteEmail(DeleteEmailResponse),
    GetEmailCount(GetEmailCountResponse),
    GetMasterPublicKey(GetMasterPublicKeyResponse),
}

#[derive(Debug, Serialize)]
pub struct GetEmailsResponse {
    pub success: bool,
    /// Base64-encoded ECIES ciphertext containing EmailData JSON
    pub encrypted_data: String,
    /// Signer's public key (hex) for encrypting outgoing emails
    pub send_pubkey: String,
    /// Next offset for inbox (if more emails available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbox_next_offset: Option<i64>,
    /// Next offset for sent (if more emails available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_next_offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SendEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Base64-encoded ECIES ciphertext containing EmailData JSON
    pub encrypted_data: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteEmailResponse {
    pub success: bool,
    pub deleted: bool,
    /// Base64-encoded ECIES ciphertext containing EmailData JSON
    pub encrypted_data: String,
}

#[derive(Debug, Serialize)]
pub struct GetEmailCountResponse {
    pub success: bool,
    pub inbox_count: i64,
    pub sent_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GetMasterPublicKeyResponse {
    pub success: bool,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

// ==================== Data Types (encrypted payload) ====================

/// Combined email data returned in encrypted_data field
#[derive(Debug, Serialize)]
pub struct EmailData {
    pub inbox: Vec<Email>,
    pub sent: Vec<SentEmail>,
}

/// Attachment metadata with base64-encoded content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    /// Base64-encoded attachment data
    pub data: String,
    /// Size in bytes (for display)
    pub size: usize,
}

#[derive(Debug, Serialize)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub body: String,
    pub received_at: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Serialize)]
pub struct SentEmail {
    pub id: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub tx_hash: Option<String>,
    pub sent_at: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

// ==================== Database Types ====================

#[derive(Debug, Deserialize)]
pub struct EncryptedEmail {
    pub id: String,
    pub sender_email: String,
    #[serde(deserialize_with = "deserialize_base64")]
    pub encrypted_data: Vec<u8>,
    pub received_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DbEmailsResponse {
    pub emails: Vec<EncryptedEmail>,
}

#[derive(Debug, Deserialize)]
pub struct DbCountResponse {
    pub count: i64,
}

#[derive(Debug, Deserialize)]
pub struct DbGenericResponse {
    pub success: bool,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedSentEmail {
    pub id: String,
    pub recipient_email: String,
    #[serde(deserialize_with = "deserialize_base64")]
    pub encrypted_data: Vec<u8>,
    pub tx_hash: Option<String>,
    pub sent_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DbSentEmailsResponse {
    pub emails: Vec<EncryptedSentEmail>,
}

#[derive(Debug, Deserialize)]
pub struct DbStoreSentResponse {
    pub success: bool,
    pub id: String,
}
