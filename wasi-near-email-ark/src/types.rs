//! Request/Response types for near.email WASI module

use serde::{Deserialize, Serialize};

// ==================== Request Types ====================

#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Get emails for an account
    GetEmails {
        account_id: String,
        signature: String,
        public_key: String,
        message: String,
        #[serde(default)]
        limit: Option<i64>,
        #[serde(default)]
        offset: Option<i64>,
    },

    /// Send email from an account
    SendEmail {
        account_id: String,
        signature: String,
        public_key: String,
        message: String,
        to: String,
        subject: String,
        body: String,
    },

    /// Delete an email
    DeleteEmail {
        account_id: String,
        signature: String,
        public_key: String,
        message: String,
        email_id: String,
    },

    /// Get email count
    GetEmailCount {
        account_id: String,
        signature: String,
        public_key: String,
        message: String,
    },

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
    pub emails: Vec<Email>,
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
