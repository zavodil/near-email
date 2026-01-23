//! Request/Response types for near.email WASI module

use serde::{Deserialize, Deserializer, Serialize};

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
    /// Get emails for the signer (authenticated via NEAR transaction)
    /// Response is encrypted with ephemeral_pubkey for client-side decryption
    GetEmails {
        /// Client's ephemeral secp256k1 public key (hex, 33 bytes compressed)
        /// WASI encrypts emails with this key, client decrypts with private key
        ephemeral_pubkey: String,
        #[serde(default)]
        limit: Option<i64>,
        #[serde(default)]
        offset: Option<i64>,
    },

    /// Send email from the signer's account
    /// Subject and body are encrypted with the signer's public key (from get_emails response)
    SendEmail {
        to: String,
        /// Base64-encoded ECIES ciphertext of subject
        encrypted_subject: String,
        /// Base64-encoded ECIES ciphertext of body
        encrypted_body: String,
    },

    /// Delete an email (must belong to signer)
    DeleteEmail {
        email_id: String,
    },

    /// Get email count for the signer
    GetEmailCount,

    /// Get master public key (for SMTP server encryption)
    /// No authentication required - public key is safe to share
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
    /// Base64-encoded ECIES ciphertext containing JSON array of emails
    /// Encrypted with client's ephemeral public key
    /// Client decrypts with ephemeral private key to get Vec<Email>
    pub encrypted_emails: String,
    /// Signer's public key (hex) for encrypting outgoing emails (subject, body)
    /// Client must encrypt with this key before sending
    pub send_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct SendEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteEmailResponse {
    pub success: bool,
    pub deleted: bool,
}

#[derive(Debug, Serialize)]
pub struct GetEmailCountResponse {
    pub success: bool,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct GetMasterPublicKeyResponse {
    pub success: bool,
    /// Compressed secp256k1 public key in hex (33 bytes = 66 hex chars)
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

// ==================== Data Types ====================

#[derive(Debug, Serialize)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub body: String,
    pub received_at: String,
}

/// Encrypted email record from database
#[derive(Debug, Deserialize)]
pub struct EncryptedEmail {
    pub id: String,
    pub sender_email: String,
    #[serde(deserialize_with = "deserialize_base64")]
    pub encrypted_data: Vec<u8>,
    pub received_at: String,
}

/// Database API response for emails
#[derive(Debug, Deserialize)]
pub struct DbEmailsResponse {
    pub emails: Vec<EncryptedEmail>,
}

/// Database API response for count
#[derive(Debug, Deserialize)]
pub struct DbCountResponse {
    pub count: i64,
}

/// Database API generic response
#[derive(Debug, Deserialize)]
pub struct DbGenericResponse {
    pub success: bool,
    #[serde(default)]
    pub deleted: bool,
}
