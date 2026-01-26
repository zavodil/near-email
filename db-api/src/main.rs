//! Database HTTP API for near.email WASI module
//!
//! Provides REST endpoints for the WASI module to access the database,
//! since WASI cannot make direct database connections.

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use rand::Rng;
use chrono::{DateTime, Utc};
use hickory_resolver::{config::*, TokioAsyncResolver};
use std::net::IpAddr;
use lettre::{
    message::{
        header::ContentType,
        Mailbox,
        MultiPart,
        SinglePart,
        Attachment as LettreAttachment,
    },
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
        extension::ClientId,
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use mail_auth::{
    common::crypto::{RsaKey, Sha256 as DkimSha256},
    common::headers::HeaderWriter,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};

/// DKIM configuration for signing outgoing emails
struct DkimConfig {
    /// RSA private key PEM for signing
    private_key_pem: String,
    /// Domain to sign for (e.g., "near.email")
    domain: String,
    /// Selector (e.g., "mail" for mail._domainkey.near.email)
    selector: String,
}

/// SMTP relay configuration for sending via external provider
struct SmtpRelayConfig {
    /// SMTP host (e.g., "smtp.resend.com")
    host: String,
    /// SMTP port (e.g., 587 for STARTTLS, 465 for SSL)
    port: u16,
    /// Username for authentication
    username: String,
    /// Password/API key for authentication
    password: String,
}

/// Rate limiter entry: (attempt_count, window_start_time)
type RateLimitEntry = (u32, DateTime<Utc>);

struct AppState {
    db: PgPool,
    email_domain: String,
    /// Account suffix to strip from account_id for email (e.g., ".testnet" or ".near")
    account_suffix: String,
    resolver: TokioAsyncResolver,
    dkim: Option<DkimConfig>,
    /// Email signature template (use %account% placeholder for sender's NEAR account)
    /// Example: "Sent by %account% via NEAR OutLayer"
    email_signature: Option<String>,
    /// SMTP relay config - if set, use relay instead of direct MX delivery
    smtp_relay: Option<SmtpRelayConfig>,
    /// API secret for authenticating requests from WASI and SMTP server
    api_secret: Option<String>,
    /// FastNEAR API URL for public key ownership verification
    /// Mainnet: https://api.fastnear.com, Testnet: https://test.api.fastnear.com
    fastnear_api_url: String,
    /// NEAR RPC URL for fallback public key verification
    /// If not set, auto-detects based on account suffix (testnet/mainnet)
    near_rpc_url: Option<String>,
    /// Rate limiter for invite code attempts (IP -> (count, window_start))
    /// Limits: 10 attempts per minute per IP
    invite_rate_limiter: Mutex<HashMap<String, RateLimitEntry>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let port: u16 = env::var("API_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("API_PORT must be a valid port");

    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    info!("Connected to database");

    // Get email domain for outgoing emails
    let email_domain = env::var("EMAIL_DOMAIN").unwrap_or_else(|_| "near.email".to_string());

    // Create DNS resolver for MX lookups (IPv4 only to avoid IPv6 connectivity issues)
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_opts);

    // Load DKIM private key for signing outgoing emails
    let dkim = match env::var("DKIM_PRIVATE_KEY") {
        Ok(key_pem) if !key_pem.is_empty() => {
            let selector = env::var("DKIM_SELECTOR").unwrap_or_else(|_| "mail".to_string());
            // Convert escaped newlines to actual newlines (common in .env files)
            let key_pem = key_pem.replace("\\n", "\n");
            // Validate the key can be parsed (try RSA PEM format)
            match RsaKey::<DkimSha256>::from_rsa_pem(&key_pem) {
                Ok(_) => {
                    info!("DKIM signing enabled with selector '{}' for domain '{}'", selector, email_domain);
                    Some(DkimConfig {
                        private_key_pem: key_pem,
                        domain: email_domain.clone(),
                        selector,
                    })
                }
                Err(e) => {
                    error!("Failed to parse DKIM private key: {}. DKIM signing disabled.", e);
                    None
                }
            }
        }
        _ => {
            warn!("DKIM_PRIVATE_KEY not set. Outgoing emails will not be DKIM signed.");
            None
        }
    };

    // Account suffix to strip from account_id for email addresses
    // .testnet for testnet, .near for mainnet (or empty string to keep full account_id)
    let account_suffix = env::var("DEFAULT_ACCOUNT_SUFFIX").unwrap_or_else(|_| ".near".to_string());

    // Email signature template - use %account% for sender's NEAR account
    // Example: "Sent by %account% via NEAR OutLayer"
    let email_signature = env::var("EMAIL_SIGNATURE").ok().filter(|s| !s.is_empty());
    if let Some(ref sig) = email_signature {
        info!("Email signature enabled: {}", sig);
    }

    // SMTP relay configuration (optional - if not set, uses direct MX delivery)
    // Set SMTP_RELAY_HOST to configure, SMTP_RELAY_ENABLED=false to disable
    let relay_enabled = env::var("SMTP_RELAY_ENABLED")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true); // enabled by default if configured

    let smtp_relay = match env::var("SMTP_RELAY_HOST") {
        Ok(host) if !host.is_empty() && relay_enabled => {
            let port: u16 = env::var("SMTP_RELAY_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .expect("SMTP_RELAY_PORT must be a valid port");
            let username = env::var("SMTP_RELAY_USER").unwrap_or_else(|_| "resend".to_string());
            let password = env::var("SMTP_RELAY_PASSWORD").expect("SMTP_RELAY_PASSWORD must be set when SMTP_RELAY_HOST is set");

            info!("SMTP relay enabled: {}:{} (user: {})", host, port, username);
            Some(SmtpRelayConfig { host, port, username, password })
        }
        Ok(host) if !host.is_empty() && !relay_enabled => {
            info!("SMTP relay configured but disabled (SMTP_RELAY_ENABLED=false), using direct MX delivery");
            None
        }
        _ => {
            info!("SMTP relay not configured, using direct MX delivery");
            None
        }
    };

    // API secret for authenticating requests (optional but recommended)
    let api_secret = env::var("API_SECRET").ok().filter(|s| !s.is_empty());
    if api_secret.is_some() {
        info!("API_SECRET configured - requests will be authenticated");
    } else {
        warn!("API_SECRET not set - API is UNPROTECTED!");
    }

    // FastNEAR API URL for public key ownership verification
    // Mainnet: https://api.fastnear.com, Testnet: https://test.api.fastnear.com
    let fastnear_api_url = env::var("FASTNEAR_API_URL")
        .unwrap_or_else(|_| "https://api.fastnear.com".to_string());
    info!("FastNEAR API URL: {}", fastnear_api_url);

    // NEAR RPC URL for fallback public key verification
    // If not set, auto-detects based on account suffix
    let near_rpc_url = env::var("NEAR_RPC_URL").ok();
    if let Some(ref url) = near_rpc_url {
        info!("NEAR RPC URL: {}", url);
    } else {
        info!("NEAR RPC URL: auto-detect based on account suffix");
    }

    info!("Email domain: {}, account suffix: {}", email_domain, account_suffix);

    let invite_rate_limiter = Mutex::new(HashMap::new());

    let state = AppState { db, email_domain, account_suffix, resolver, dkim, email_signature, smtp_relay, api_secret, fastnear_api_url, near_rpc_url, invite_rate_limiter };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let shared_state = Arc::new(state);

    // Protected routes (require API_SECRET)
    let protected_routes = Router::new()
        .route("/emails", get(get_emails))
        .route("/emails/count", get(count_emails))
        .route("/emails/:id", delete(delete_email))
        .route("/send", post(send_email))
        .route("/internal-store", post(store_internal_email))
        .route("/sent-emails", get(get_sent_emails))
        .route("/request-email", get(request_email))
        .route("/store-sent", post(store_sent_email))
        .route("/attachments", post(store_attachment))
        .route("/attachments/:id", get(get_attachment))
        // Admin routes (protected)
        .route("/admin/invites/grant", post(admin_grant_invites))
        .route("/admin/invites/seed-user", post(admin_seed_user))
        // Blacklist admin routes
        .route("/admin/blacklist/add", post(admin_blacklist_add))
        .route("/admin/blacklist/remove", post(admin_blacklist_remove))
        .route("/admin/blacklist/check", get(admin_blacklist_check))
        // Stats route
        .route("/admin/stats", get(admin_get_stats))
        .layer(middleware::from_fn_with_state(shared_state.clone(), require_api_secret));

    // Public routes (no auth needed)
    let public_routes = Router::new()
        .route("/health", get(health))
        // Invite routes (public - called by frontend, have their own protection logic)
        .route("/invites/check-user", get(check_user))
        .route("/invites/use", post(use_invite))
        .route("/invites/generate", post(generate_invite))
        .route("/invites/send-email", post(send_invite_email))
        .route("/invites/my", post(my_invites));

    let app = Router::new()
        .merge(protected_routes)
        .merge(public_routes)
        .layer(cors)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB for large attachments
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting DB API on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

// ==================== Middleware ====================

/// Middleware to check API secret
async fn require_api_secret(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // If no secret configured, allow all requests (but warn was logged at startup)
    let Some(expected_secret) = &state.api_secret else {
        return Ok(next.run(req).await);
    };

    // Check X-API-Secret header
    let provided_secret = req
        .headers()
        .get("X-API-Secret")
        .and_then(|v| v.to_str().ok());

    match provided_secret {
        Some(secret) if secret == expected_secret => Ok(next.run(req).await),
        Some(_) => {
            warn!("Invalid API secret provided");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!("Missing X-API-Secret header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// ==================== Types ====================

#[derive(Debug, Deserialize)]
struct GetEmailsQuery {
    recipient: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, FromRow)]
struct EmailRow {
    id: Uuid,
    sender_email: String,
    encrypted_data: Vec<u8>,
    received_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct EmailRecord {
    id: String,
    sender_email: String,
    #[serde(with = "base64_serde")]
    encrypted_data: Vec<u8>,
    received_at: String,
}

#[derive(Debug, Serialize)]
struct EmailsResponse {
    emails: Vec<EmailRecord>,
}

#[derive(Debug, Serialize)]
struct CountResponse {
    count: i64,
}

#[derive(Debug, Deserialize)]
struct DeleteEmailBody {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    success: bool,
    deleted: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Attachment {
    filename: String,
    content_type: String,
    /// Base64-encoded attachment data
    data: String,
    #[allow(dead_code)]
    size: usize,
}

#[derive(Debug, Deserialize)]
struct SendEmailBody {
    from_account: String,
    to: String,
    subject: String,
    body: String,
    #[serde(default)]
    attachments: Vec<Attachment>,
}

#[derive(Debug, Serialize)]
struct SendResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Request to store an internal (pre-encrypted) email
#[derive(Debug, Deserialize)]
struct StoreInternalEmailBody {
    recipient: String,
    sender_email: String,
    #[serde(with = "base64_serde_de")]
    encrypted_data: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct StoreInternalResponse {
    success: bool,
    id: String,
}

#[derive(Debug, Deserialize)]
struct GetSentEmailsQuery {
    sender: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

#[derive(Debug, Deserialize)]
struct RequestEmailQuery {
    /// account_id is used as both recipient (for inbox) and sender (for sent)
    account_id: String,
    #[serde(default = "default_limit")]
    inbox_limit: i64,
    #[serde(default)]
    inbox_offset: i64,
    #[serde(default = "default_limit")]
    sent_limit: i64,
    #[serde(default)]
    sent_offset: i64,
}

#[derive(Debug, Serialize)]
struct RequestEmailResponse {
    inbox: Vec<EmailRecord>,
    sent: Vec<SentEmailRecord>,
    inbox_count: i64,
    sent_count: i64,
}

#[derive(Debug, FromRow)]
struct SentEmailRow {
    id: Uuid,
    recipient_email: String,
    encrypted_data: Vec<u8>,
    tx_hash: Option<String>,
    sent_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SentEmailRecord {
    id: String,
    recipient_email: String,
    #[serde(with = "base64_serde")]
    encrypted_data: Vec<u8>,
    tx_hash: Option<String>,
    sent_at: String,
}

#[derive(Debug, Serialize)]
struct SentEmailsResponse {
    emails: Vec<SentEmailRecord>,
}

/// Request to store a sent email (already encrypted by WASI module)
#[derive(Debug, Deserialize)]
struct StoreSentEmailBody {
    sender: String,
    recipient_email: String,
    #[serde(with = "base64_serde_de")]
    encrypted_data: Vec<u8>,
    tx_hash: Option<String>,
    /// Optional client-provided ID (for pre-storing attachments with consistent email_id)
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
struct StoreSentResponse {
    success: bool,
    id: String,
}

/// Request to store an attachment (for lazy loading)
#[derive(Debug, Deserialize)]
struct StoreAttachmentBody {
    email_id: String,
    folder: String,  // "inbox" or "sent"
    recipient: String,
    filename: String,
    content_type: String,
    size: i32,
    #[serde(with = "base64_serde_de")]
    encrypted_data: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct StoreAttachmentResponse {
    success: bool,
    id: String,
}

/// Query for getting attachment
#[derive(Debug, Deserialize)]
struct GetAttachmentQuery {
    recipient: String,
}

#[derive(Debug, FromRow)]
struct AttachmentRow {
    id: Uuid,
    email_id: Uuid,
    folder: String,
    recipient: String,
    filename: String,
    content_type: String,
    size: i32,
    encrypted_data: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct AttachmentResponse {
    id: String,
    email_id: String,
    folder: String,
    filename: String,
    content_type: String,
    size: i32,
    #[serde(with = "base64_serde")]
    encrypted_data: Vec<u8>,
}

// Base64 deserialization helper
mod base64_serde_de {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

// Base64 serialization helper
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(data))
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

// ==================== Handlers ====================

async fn health() -> &'static str {
    "ok"
}

async fn get_emails(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetEmailsQuery>,
) -> Result<Json<EmailsResponse>, StatusCode> {
    let rows: Vec<EmailRow> = sqlx::query_as(
        r#"
        SELECT id, sender_email, encrypted_data, received_at
        FROM emails
        WHERE recipient = $1
        ORDER BY received_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&query.recipient)
    .bind(query.limit)
    .bind(query.offset)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let emails = rows
        .into_iter()
        .map(|row| EmailRecord {
            id: row.id.to_string(),
            sender_email: row.sender_email,
            encrypted_data: row.encrypted_data,
            received_at: row.received_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(EmailsResponse { emails }))
}

async fn count_emails(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetEmailsQuery>,
) -> Result<Json<CountResponse>, StatusCode> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM emails WHERE recipient = $1",
    )
    .bind(&query.recipient)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CountResponse { count: count.0 }))
}

async fn delete_email(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<DeleteEmailBody>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let result = sqlx::query(
        "DELETE FROM emails WHERE id = $1 AND recipient = $2",
    )
    .bind(uuid)
    .bind(&body.account_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(DeleteResponse {
        success: true,
        deleted: result.rows_affected() > 0,
    }))
}

async fn send_email(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SendEmailBody>,
) -> Result<Json<SendResponse>, StatusCode> {
    // Check access (registration + not blacklisted)
    match check_account_access(&state.db, &body.from_account).await? {
        AccessCheck::Allowed => {}
        AccessCheck::NotRegistered => {
            return Ok(Json(SendResponse {
                success: false,
                error: Some("Account not registered. Please use an invite code to join.".to_string()),
            }));
        }
        AccessCheck::Blacklisted(reason) => {
            return Ok(Json(SendResponse {
                success: false,
                error: Some(format!("Account suspended: {}", reason)),
            }));
        }
    }

    // Log only metadata, not content (privacy)
    info!(
        "📤 Send email request: from={}, to={}, subject_len={}, body_len={}",
        body.from_account, body.to, body.subject.len(), body.body.len()
    );

    // Build from address - strip account suffix from account_id
    // zavodil.testnet -> zavodil@near.email (on testnet)
    // zavodil.near -> zavodil@near.email (on mainnet)
    let from_local = body.from_account
        .strip_suffix(&state.account_suffix)
        .unwrap_or(&body.from_account);
    let from_email = format!("{}@{}", from_local, state.email_domain);
    let from_mailbox: Mailbox = from_email
        .parse()
        .map_err(|e| {
            error!("Invalid from address {}: {}", from_email, e);
            StatusCode::BAD_REQUEST
        })?;

    // Parse to address
    let to_mailbox: Mailbox = body.to
        .parse()
        .map_err(|e| {
            error!("Invalid to address {}: {}", body.to, e);
            StatusCode::BAD_REQUEST
        })?;

    // Extract recipient domain for MX lookup
    let to_domain = body.to
        .split('@')
        .nth(1)
        .ok_or_else(|| {
            error!("No domain in to address: {}", body.to);
            StatusCode::BAD_REQUEST
        })?;

    // Generate unique Message-ID
    let message_id = format!("<{}.{}@{}>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp(),
        state.email_domain
    );

    // Use body as-is - signature is added by WASM before calling this API
    let email_body = body.body.clone();

    // Build email message (with or without attachments)
    let email = if body.attachments.is_empty() {
        // Simple text email
        Message::builder()
            .from(from_mailbox.clone())
            .to(to_mailbox.clone())
            .subject(&body.subject)
            .message_id(Some(message_id))
            .header(ContentType::TEXT_PLAIN)
            .body(email_body)
            .map_err(|e| {
                error!("Failed to build email: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        // Multipart email with attachments
        use base64::{engine::general_purpose::STANDARD, Engine};

        info!("Building email with {} attachment(s)", body.attachments.len());

        // Create text body part
        let text_part = SinglePart::plain(email_body);

        // Start with multipart/mixed
        let mut multipart = MultiPart::mixed().singlepart(text_part);

        // Add each attachment
        for att in &body.attachments {
            let decoded_data = STANDARD.decode(&att.data).map_err(|e| {
                error!("Failed to decode attachment {}: {}", att.filename, e);
                StatusCode::BAD_REQUEST
            })?;

            // Parse content type
            let content_type = ContentType::parse(&att.content_type).unwrap_or(ContentType::TEXT_PLAIN);

            let attachment_part = LettreAttachment::new(att.filename.clone())
                .body(decoded_data, content_type);

            multipart = multipart.singlepart(attachment_part);
        }

        Message::builder()
            .from(from_mailbox.clone())
            .to(to_mailbox.clone())
            .subject(&body.subject)
            .message_id(Some(message_id))
            .multipart(multipart)
            .map_err(|e| {
                error!("Failed to build multipart email: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

    // Send via relay or direct MX
    let send_result = if let Some(relay) = &state.smtp_relay {
        // Use SMTP relay (e.g., Resend, SendGrid)
        info!("Sending via SMTP relay {}:{}", relay.host, relay.port);
        send_via_relay(relay, &email).await
    } else {
        // Direct MX delivery
        // Lookup MX records
        let mx_records = state.resolver
            .mx_lookup(to_domain)
            .await
            .map_err(|e| {
                error!("MX lookup failed for {}: {}", to_domain, e);
                StatusCode::BAD_GATEWAY
            })?;

        // Get the highest priority MX server (lowest preference number)
        let mx_host = mx_records
            .iter()
            .min_by_key(|mx| mx.preference())
            .map(|mx| mx.exchange().to_string().trim_end_matches('.').to_string())
            .ok_or_else(|| {
                error!("No MX records found for {}", to_domain);
                StatusCode::BAD_GATEWAY
            })?;

        info!("Using MX server {} for {}", mx_host, to_domain);

        // Sign with DKIM and send, or send unsigned
        if let Some(dkim) = &state.dkim {
            match sign_email_dkim(&email, dkim) {
                Ok(signed_bytes) => {
                    info!("Email DKIM signed successfully");
                    // Create envelope for raw sending
                    match lettre::address::Envelope::new(
                        Some(from_mailbox.email.clone()),
                        vec![to_mailbox.email.clone()],
                    ) {
                        Ok(envelope) => send_via_smtp_raw(&state.resolver, &mx_host, &state.email_domain, &envelope, &signed_bytes).await,
                        Err(e) => Err(format!("Failed to create envelope: {}", e)),
                    }
                }
                Err(e) => {
                    warn!("DKIM signing failed, sending unsigned: {}", e);
                    send_via_smtp(&state.resolver, &mx_host, &state.email_domain, &email).await
                }
            }
        } else {
            send_via_smtp(&state.resolver, &mx_host, &state.email_domain, &email).await
        }
    };

    let via = state.smtp_relay.as_ref().map(|r| r.host.as_str()).unwrap_or(to_domain);
    match send_result {
        Ok(_) => {
            info!("Email sent successfully to {} via {}", body.to, via);
            // Increment sent stats
            increment_sent_stats(&state.db, &body.from_account).await;
            Ok(Json(SendResponse { success: true, error: None }))
        }
        Err(e) => {
            error!("Failed to send email to {} via {}: {}", body.to, via, e);
            Ok(Json(SendResponse {
                success: false,
                error: Some(format!("SMTP error: {}", e))
            }))
        }
    }
}

/// Sign email with DKIM and return raw signed bytes
fn sign_email_dkim(email: &Message, dkim: &DkimConfig) -> Result<Vec<u8>, String> {
    use mail_auth::dkim::DkimSigner;

    // Get raw email bytes
    let raw_email = email.formatted();

    // Create RSA key from PEM
    let pk = RsaKey::<DkimSha256>::from_rsa_pem(&dkim.private_key_pem)
        .map_err(|e| format!("Failed to parse DKIM key: {}", e))?;

    // Create DKIM signer
    let signer = DkimSigner::from_key(pk)
        .domain(&dkim.domain)
        .selector(&dkim.selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(&raw_email)
        .map_err(|e| format!("DKIM signing failed: {}", e))?;

    // Get the DKIM-Signature header
    let dkim_header = signer.to_header();

    // Prepend DKIM-Signature header to the message
    let signed_raw = format!("{}{}", dkim_header, String::from_utf8_lossy(&raw_email));

    Ok(signed_raw.into_bytes())
}

/// Resolve hostname to IPv4 address using our resolver
async fn resolve_to_ipv4(resolver: &TokioAsyncResolver, hostname: &str) -> Result<IpAddr, String> {
    let lookup = resolver
        .lookup_ip(hostname)
        .await
        .map_err(|e| format!("DNS lookup failed for {}: {}", hostname, e))?;

    // Get the first IPv4 address
    lookup
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| format!("No IPv4 address found for {}", hostname))
}

/// Send email via SMTP with TLS (IPv4 only)
async fn send_via_smtp(
    resolver: &TokioAsyncResolver,
    mx_host: &str,
    email_domain: &str,
    email: &Message,
) -> Result<(), String> {
    // Resolve MX hostname to IPv4 address (bypass lettre's internal DNS which returns IPv6)
    let ip_addr = resolve_to_ipv4(resolver, mx_host).await?;
    info!("Resolved {} to IPv4: {}", mx_host, ip_addr);

    // TLS parameters with hostname for certificate validation
    let tls_params = TlsParameters::builder(mx_host.to_string())
        .dangerous_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("TLS params error: {}", e))?;

    // HELO name should be mail.domain (matches MX record)
    let helo_name = format!("mail.{}", email_domain);

    // Connect to IP directly with STARTTLS
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(ip_addr.to_string())
        .port(25)
        .hello_name(ClientId::Domain(helo_name.clone()))
        .tls(Tls::Required(tls_params.clone()))
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    match mailer.send(email.clone()).await {
        Ok(_) => return Ok(()),
        Err(e) => {
            warn!("STARTTLS failed for {} ({}), trying opportunistic: {}", mx_host, ip_addr, e);
        }
    }

    // Fall back to opportunistic TLS (try TLS but allow plaintext)
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(ip_addr.to_string())
        .port(25)
        .hello_name(ClientId::Domain(helo_name))
        .tls(Tls::Opportunistic(tls_params))
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    mailer
        .send(email.clone())
        .await
        .map_err(|e| format!("SMTP send error: {}", e))?;

    Ok(())
}

/// Send raw email bytes via SMTP (for DKIM-signed messages, IPv4 only)
async fn send_via_smtp_raw(
    resolver: &TokioAsyncResolver,
    mx_host: &str,
    email_domain: &str,
    envelope: &lettre::address::Envelope,
    raw_email: &[u8],
) -> Result<(), String> {
    // Resolve MX hostname to IPv4 address (bypass lettre's internal DNS which returns IPv6)
    let ip_addr = resolve_to_ipv4(resolver, mx_host).await?;
    info!("Resolved {} to IPv4: {}", mx_host, ip_addr);

    // TLS parameters with hostname for certificate validation
    let tls_params = TlsParameters::builder(mx_host.to_string())
        .dangerous_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("TLS params error: {}", e))?;

    // HELO name should be mail.domain (matches MX record)
    let helo_name = format!("mail.{}", email_domain);

    // Connect to IP directly with STARTTLS
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(ip_addr.to_string())
        .port(25)
        .hello_name(ClientId::Domain(helo_name.clone()))
        .tls(Tls::Required(tls_params.clone()))
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    match mailer.send_raw(envelope, raw_email).await {
        Ok(_) => return Ok(()),
        Err(e) => {
            warn!("STARTTLS failed for {} ({}), trying opportunistic: {}", mx_host, ip_addr, e);
        }
    }

    // Fall back to opportunistic TLS
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(ip_addr.to_string())
        .port(25)
        .hello_name(ClientId::Domain(helo_name))
        .tls(Tls::Opportunistic(tls_params))
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    mailer
        .send_raw(envelope, raw_email)
        .await
        .map_err(|e| format!("SMTP send error: {}", e))?;

    Ok(())
}

/// Send email via SMTP relay (Resend, SendGrid, etc.)
async fn send_via_relay(
    relay: &SmtpRelayConfig,
    email: &Message,
) -> Result<(), String> {
    let creds = Credentials::new(relay.username.clone(), relay.password.clone());

    // Use STARTTLS on port 587, or implicit TLS on port 465
    let mailer = if relay.port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&relay.host)
            .map_err(|e| format!("Failed to create relay transport: {}", e))?
            .credentials(creds)
            .port(relay.port)
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build()
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&relay.host)
            .map_err(|e| format!("Failed to create relay transport: {}", e))?
            .credentials(creds)
            .port(relay.port)
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build()
    };

    mailer
        .send(email.clone())
        .await
        .map_err(|e| format!("SMTP relay error: {}", e))?;

    Ok(())
}

/// Store an internal email (already encrypted by WASI module)
/// Used for NEAR-to-NEAR messaging without external SMTP
async fn store_internal_email(
    State(state): State<Arc<AppState>>,
    Json(body): Json<StoreInternalEmailBody>,
) -> Result<Json<StoreInternalResponse>, StatusCode> {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO emails (id, recipient, sender_email, encrypted_data, received_at)
        VALUES ($1, $2, $3, $4, NOW())
        "#,
    )
    .bind(id)
    .bind(&body.recipient)
    .bind(&body.sender_email)
    .bind(&body.encrypted_data)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to store internal email: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "📧 Internal email {} stored: to={}, from={}, encrypted={}B",
        id, body.recipient, body.sender_email, body.encrypted_data.len()
    );

    // Increment received stats for recipient
    increment_received_stats(&state.db, &body.recipient).await;

    Ok(Json(StoreInternalResponse {
        success: true,
        id: id.to_string(),
    }))
}

/// Get sent emails for a sender
async fn get_sent_emails(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetSentEmailsQuery>,
) -> Result<Json<SentEmailsResponse>, StatusCode> {
    let rows: Vec<SentEmailRow> = sqlx::query_as(
        r#"
        SELECT id, recipient_email, encrypted_data, tx_hash, sent_at
        FROM sent_emails
        WHERE sender = $1
        ORDER BY sent_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&query.sender)
    .bind(query.limit)
    .bind(query.offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to get sent emails: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let emails = rows
        .into_iter()
        .map(|row| SentEmailRecord {
            id: row.id.to_string(),
            recipient_email: row.recipient_email,
            encrypted_data: row.encrypted_data,
            tx_hash: row.tx_hash,
            sent_at: row.sent_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(SentEmailsResponse { emails }))
}

/// Get combined inbox and sent emails in a single request
/// Optimizes round-trip time by fetching emails and counts in parallel DB queries
async fn request_email(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RequestEmailQuery>,
) -> Result<Json<RequestEmailResponse>, StatusCode> {
    // Check access (registration + not blacklisted)
    match check_account_access(&state.db, &query.account_id).await? {
        AccessCheck::Allowed => {}
        AccessCheck::NotRegistered => {
            // Return empty response for unregistered users (they can still see if they have pending emails)
            // but they cannot access the actual content
            return Ok(Json(RequestEmailResponse {
                inbox: vec![],
                sent: vec![],
                inbox_count: 0,
                sent_count: 0,
            }));
        }
        AccessCheck::Blacklisted(_) => {
            return Ok(Json(RequestEmailResponse {
                inbox: vec![],
                sent: vec![],
                inbox_count: 0,
                sent_count: 0,
            }));
        }
    }

    // Run all queries in parallel: inbox, sent, inbox_count, sent_count
    let (inbox_result, sent_result, inbox_count_result, sent_count_result) = tokio::join!(
        sqlx::query_as::<_, EmailRow>(
            r#"
            SELECT id, sender_email, encrypted_data, received_at
            FROM emails
            WHERE recipient = $1
            ORDER BY received_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&query.account_id)
        .bind(query.inbox_limit)
        .bind(query.inbox_offset)
        .fetch_all(&state.db),

        sqlx::query_as::<_, SentEmailRow>(
            r#"
            SELECT id, recipient_email, encrypted_data, tx_hash, sent_at
            FROM sent_emails
            WHERE sender = $1
            ORDER BY sent_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&query.account_id)
        .bind(query.sent_limit)
        .bind(query.sent_offset)
        .fetch_all(&state.db),

        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM emails WHERE recipient = $1")
            .bind(&query.account_id)
            .fetch_one(&state.db),

        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM sent_emails WHERE sender = $1")
            .bind(&query.account_id)
            .fetch_one(&state.db)
    );

    let inbox_rows = inbox_result.map_err(|e| {
        error!("Failed to get inbox emails: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sent_rows = sent_result.map_err(|e| {
        error!("Failed to get sent emails: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let inbox_count = inbox_count_result.map(|r| r.0).unwrap_or(0);
    let sent_count = sent_count_result.map(|r| r.0).unwrap_or(0);

    let inbox = inbox_rows
        .into_iter()
        .map(|row| EmailRecord {
            id: row.id.to_string(),
            sender_email: row.sender_email,
            encrypted_data: row.encrypted_data,
            received_at: row.received_at.to_rfc3339(),
        })
        .collect();

    let sent = sent_rows
        .into_iter()
        .map(|row| SentEmailRecord {
            id: row.id.to_string(),
            recipient_email: row.recipient_email,
            encrypted_data: row.encrypted_data,
            tx_hash: row.tx_hash,
            sent_at: row.sent_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(RequestEmailResponse { inbox, sent, inbox_count, sent_count }))
}

/// Store a sent email (already encrypted by WASI module)
async fn store_sent_email(
    State(state): State<Arc<AppState>>,
    Json(body): Json<StoreSentEmailBody>,
) -> Result<Json<StoreSentResponse>, StatusCode> {
    // Use client-provided ID if valid UUID, otherwise generate new one
    let id = match &body.id {
        Some(id_str) => Uuid::parse_str(id_str).unwrap_or_else(|_| Uuid::new_v4()),
        None => Uuid::new_v4(),
    };

    sqlx::query(
        r#"
        INSERT INTO sent_emails (id, sender, recipient_email, encrypted_data, tx_hash, sent_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(id)
    .bind(&body.sender)
    .bind(&body.recipient_email)
    .bind(&body.encrypted_data)
    .bind(&body.tx_hash)
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to store sent email: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "📤 Sent email {} stored: from={}, to={}, encrypted={}B, tx_hash={:?}",
        id, body.sender, body.recipient_email, body.encrypted_data.len(), body.tx_hash
    );

    Ok(Json(StoreSentResponse {
        success: true,
        id: id.to_string(),
    }))
}

/// Insert signature before quoted text markers, or at the end if no quote found
fn insert_signature_before_quote(body: &str, signature: &str) -> String {
    // Common quote markers
    let quote_markers = [
        "-------- Original Message --------",
        "---------- Forwarded message ---------",
    ];

    // Find earliest quote marker position
    let mut earliest_pos: Option<usize> = None;

    for marker in &quote_markers {
        if let Some(pos) = body.find(marker) {
            earliest_pos = Some(earliest_pos.map_or(pos, |e| e.min(pos)));
        }
    }

    // Check for "On ... wrote:" pattern (common in Gmail replies)
    if let Some(on_pos) = body.find("\nOn ") {
        let after_on = &body[on_pos..];
        if after_on.contains("wrote:") || after_on.contains("написал:") {
            earliest_pos = Some(earliest_pos.map_or(on_pos, |e| e.min(on_pos)));
        }
    }

    if let Some(pos) = earliest_pos {
        // Insert signature before the quoted text
        let (before, after) = body.split_at(pos);
        let before_trimmed = before.trim_end();
        format!("{}\n\n--\n{}\n\n{}", before_trimmed, signature, after)
    } else {
        // No quote found, append at the end
        format!("{}\n\n--\n{}", body, signature)
    }
}

/// Store an attachment for lazy loading
/// Used by WASI module when attachment is too large to include inline
async fn store_attachment(
    State(state): State<Arc<AppState>>,
    Json(body): Json<StoreAttachmentBody>,
) -> Result<Json<StoreAttachmentResponse>, StatusCode> {
    let id = Uuid::new_v4();
    let email_id = Uuid::parse_str(&body.email_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    sqlx::query(
        r#"
        INSERT INTO attachments (id, email_id, folder, recipient, filename, content_type, size, encrypted_data, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        "#,
    )
    .bind(id)
    .bind(email_id)
    .bind(&body.folder)
    .bind(&body.recipient)
    .bind(&body.filename)
    .bind(&body.content_type)
    .bind(body.size)
    .bind(&body.encrypted_data)
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to store attachment: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "📎 Attachment {} stored: email={}, file={}, size={}B",
        id, body.email_id, body.filename, body.size
    );

    Ok(Json(StoreAttachmentResponse {
        success: true,
        id: id.to_string(),
    }))
}

/// Get an attachment by ID (must belong to recipient)
async fn get_attachment(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<GetAttachmentQuery>,
) -> Result<Json<AttachmentResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let row: AttachmentRow = sqlx::query_as(
        r#"
        SELECT id, email_id, folder, recipient, filename, content_type, size, encrypted_data
        FROM attachments
        WHERE id = $1 AND recipient = $2
        "#,
    )
    .bind(uuid)
    .bind(&query.recipient)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to get attachment: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    info!("📎 Attachment {} fetched for {}", id, query.recipient);

    Ok(Json(AttachmentResponse {
        id: row.id.to_string(),
        email_id: row.email_id.to_string(),
        folder: row.folder,
        filename: row.filename,
        content_type: row.content_type,
        size: row.size,
        encrypted_data: row.encrypted_data,
    }))
}

// ==================== Invite System ====================

/// Generate a random invite code (8 chars, alphanumeric)
fn generate_invite_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No I/O/0/1 to avoid confusion
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// Invite types
#[derive(Debug, Deserialize)]
struct CheckUserQuery {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct CheckUserResponse {
    registered: bool,
    invites_enabled: bool,
}

// ==================== Signature Verification ====================

/// Signed request for invite operations (NEP-413 format)
/// Message format: "near.email:{action}:{account_id}:{timestamp_ms}"
#[derive(Debug, Deserialize)]
struct SignedRequest {
    account_id: String,
    /// Base64 encoded ed25519 signature
    signature: String,
    /// Public key in NEAR format (ed25519:xxx)
    public_key: String,
    /// Timestamp in milliseconds (for replay protection)
    timestamp_ms: u64,
    /// Base64 encoded 32-byte nonce (required for NEP-413 verification)
    nonce: String,
}

/// NEP-413 payload structure for Borsh serialization
/// See: https://github.com/near/NEPs/blob/master/neps/nep-0413.md
#[derive(borsh::BorshSerialize)]
struct Nep413Payload {
    /// The message that was requested to be signed
    message: String,
    /// 32-byte nonce
    nonce: [u8; 32],
    /// The recipient to whom the signature is intended for
    recipient: String,
    /// Optional callback URL (always None for our use case)
    callback_url: Option<String>,
}

/// NEP-413 tag: 2^31 + 413
const NEP413_TAG: u32 = 2147484061;

/// Response from FastNEAR API for public key lookup
#[derive(Debug, Deserialize)]
struct FastNearPublicKeyResponse {
    account_ids: Vec<String>,
}

/// NEAR RPC response for access key list
#[derive(Debug, Deserialize)]
struct NearRpcResponse {
    result: Option<NearRpcAccessKeyList>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NearRpcAccessKeyList {
    keys: Vec<NearRpcAccessKey>,
}

#[derive(Debug, Deserialize)]
struct NearRpcAccessKey {
    public_key: String,
}

/// Verify public key ownership via NEAR RPC (fallback when FastNEAR fails)
async fn verify_access_key_owner_via_rpc(
    near_rpc_url: Option<&str>,
    public_key: &str,
    account_id: &str,
) -> Result<(), String> {
    // Use provided RPC URL or auto-detect based on account suffix
    let rpc_url = near_rpc_url.unwrap_or_else(|| {
        if account_id.ends_with(".testnet") {
            "https://rpc.testnet.near.org"
        } else {
            "https://rpc.mainnet.near.org"
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "query",
            "params": {
                "request_type": "view_access_key_list",
                "finality": "final",
                "account_id": account_id
            }
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("NEAR RPC request failed: {}", e))?;

    let data: NearRpcResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse NEAR RPC response: {}", e))?;

    if let Some(error) = data.error {
        return Err(format!("NEAR RPC error: {}", error));
    }

    let keys = data.result
        .ok_or_else(|| "No result in NEAR RPC response".to_string())?
        .keys;

    if keys.iter().any(|k| k.public_key == public_key) {
        Ok(())
    } else {
        Err(format!(
            "Public key {} not found in account {} access keys",
            public_key, account_id
        ))
    }
}

/// Verify that a public key belongs to the claimed account_id
/// First tries FastNEAR API, falls back to NEAR RPC if FastNEAR returns empty
/// Returns Ok(()) if key ownership verified, Err(reason) otherwise
async fn verify_access_key_owner(
    fastnear_api_url: &str,
    near_rpc_url: Option<&str>,
    public_key: &str,
    account_id: &str,
) -> Result<(), String> {
    // FastNEAR API expects key without ed25519: prefix
    // e.g., https://test.api.fastnear.com/v1/public_key/5Uu8xpn2hEAcxpKcBx4GrMnwV4dddfQbBv8PGmEkKyDx
    let key_without_prefix = public_key.strip_prefix("ed25519:").unwrap_or(public_key);
    let url = format!("{}/v1/public_key/{}", fastnear_api_url, key_without_prefix);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("FastNEAR API request failed: {}", e))?;

    if !response.status().is_success() {
        // 404 means public key not found on chain
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("Public key not found on chain".to_string());
        }
        return Err(format!("FastNEAR API error: {}", response.status()));
    }

    let data: FastNearPublicKeyResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse FastNEAR response: {}", e))?;

    if data.account_ids.contains(&account_id.to_string()) {
        return Ok(());
    }

    // FastNEAR returned empty or doesn't have this account - fall back to NEAR RPC
    if data.account_ids.is_empty() {
        tracing::info!(
            "FastNEAR returned empty for key {}, falling back to NEAR RPC",
            public_key
        );
        return verify_access_key_owner_via_rpc(near_rpc_url, public_key, account_id).await;
    }

    Err(format!(
        "Public key does not belong to account {}. Key belongs to: {:?}",
        account_id,
        data.account_ids
    ))
}

/// Verify ed25519 signature for invite requests using NEP-413 format
/// NEP-413 specifies that the signed payload is: SHA256(NEP413_TAG || Borsh(Nep413Payload))
/// Returns Ok(()) if signature is valid, Err(reason) otherwise
fn verify_signature_crypto(signed: &SignedRequest, action: &str) -> Result<(), String> {
    // Check timestamp (allow 1 hour window)
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let one_hour_ms = 60 * 60 * 1000;
    if signed.timestamp_ms > now_ms + one_hour_ms {
        return Err("Timestamp is in the future".to_string());
    }
    if now_ms > signed.timestamp_ms + one_hour_ms {
        return Err("Signature expired".to_string());
    }

    // Parse public key (format: "ed25519:base58...")
    let pubkey_parts: Vec<&str> = signed.public_key.split(':').collect();
    if pubkey_parts.len() != 2 || pubkey_parts[0] != "ed25519" {
        return Err("Invalid public key format, expected 'ed25519:base58...'".to_string());
    }

    let pubkey_bytes = bs58::decode(pubkey_parts[1])
        .into_vec()
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    if pubkey_bytes.len() != 32 {
        return Err(format!("Invalid public key length: {} (expected 32)", pubkey_bytes.len()));
    }

    // Decode signature (base64)
    let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signed.signature)
        .map_err(|e| format!("Failed to decode signature: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: {} (expected 64)", sig_bytes.len()));
    }

    // Decode nonce (base64) - must be exactly 32 bytes
    let nonce_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signed.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

    if nonce_bytes.len() != 32 {
        return Err(format!("Invalid nonce length: {} (expected 32)", nonce_bytes.len()));
    }

    let nonce_array: [u8; 32] = nonce_bytes.try_into()
        .map_err(|_| "Failed to convert nonce to array".to_string())?;

    // Build message
    let message = format!(
        "near.email:{}:{}:{}",
        action, signed.account_id, signed.timestamp_ms
    );

    // Build NEP-413 payload
    let payload = Nep413Payload {
        message,
        nonce: nonce_array,
        recipient: "near.email".to_string(),
        callback_url: None,
    };

    // Serialize payload with Borsh
    let payload_bytes = borsh::to_vec(&payload)
        .map_err(|e| format!("Failed to serialize NEP-413 payload: {}", e))?;

    // Build final message: tag (4 bytes LE) + payload
    let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
    to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
    to_hash.extend_from_slice(&payload_bytes);

    // SHA256 hash the combined data
    let hash = Sha256::digest(&to_hash);

    // Verify using ed25519
    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(pubkey_bytes.as_slice())
            .map_err(|_| "Invalid public key bytes".to_string())?
    ).map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(sig_bytes.as_slice())
            .map_err(|_| "Invalid signature bytes".to_string())?
    );

    // Verify signature against the hash
    verifying_key
        .verify(&hash, &signature)
        .map_err(|_| "Signature verification failed".to_string())?;

    Ok(())
}

/// Full signature verification: cryptographic check + public key ownership verification
/// Returns Ok(()) if signature is valid AND key belongs to account, Err(reason) otherwise
///
/// Flow:
/// 1. Verify ed25519 signature cryptographically (+ timestamp check for replay protection)
/// 2. Verify public key belongs to claimed account_id via FastNEAR API
async fn verify_signature_with_ownership(
    fastnear_api_url: &str,
    near_rpc_url: Option<&str>,
    signed: &SignedRequest,
    action: &str,
) -> Result<(), String> {
    // Step 1: Verify cryptographic signature
    verify_signature_crypto(signed, action)?;

    // Step 2: Verify public key belongs to the claimed account_id via FastNEAR API
    // This only works for NEAR access keys, not for derived payment keys
    verify_access_key_owner(fastnear_api_url, near_rpc_url, &signed.public_key, &signed.account_id).await?;

    Ok(())
}

// ==================== Invite Types ====================

#[derive(Debug, Deserialize)]
struct UseInviteBody {
    code: String,
    account_id: String,
}

#[derive(Debug, Serialize)]
struct UseInviteResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GenerateInviteBody {
    account_id: String,
    /// Base64 encoded ed25519 signature
    signature: String,
    /// Public key in NEAR format (ed25519:xxx)
    public_key: String,
    /// Timestamp in milliseconds
    timestamp_ms: u64,
    /// Base64 encoded 32-byte nonce
    nonce: String,
}

#[derive(Debug, Serialize)]
struct GenerateInviteResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SendInviteBody {
    account_id: String,
    recipient_email: String,
    /// Base64 encoded ed25519 signature
    signature: String,
    /// Public key in NEAR format (ed25519:xxx)
    public_key: String,
    /// Timestamp in milliseconds
    timestamp_ms: u64,
    /// Base64 encoded 32-byte nonce
    nonce: String,
}

#[derive(Debug, Serialize)]
struct SendInviteResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MyInvitesBody {
    account_id: String,
    /// Base64 encoded ed25519 signature
    signature: String,
    /// Public key in NEAR format (ed25519:xxx)
    public_key: String,
    /// Timestamp in milliseconds
    timestamp_ms: u64,
    /// Base64 encoded 32-byte nonce
    nonce: String,
}

#[derive(Debug, FromRow)]
struct InviteRow {
    id: Uuid,
    code: String,
    recipient_email: Option<String>,
    used_by_account_id: Option<String>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct InviteRecord {
    id: String,
    code: String,
    recipient_email: Option<String>,
    used_by: Option<String>,
    used_at: Option<String>,
    created_at: String,
    expires_at: String,
    status: String, // "pending", "used", "expired"
}

#[derive(Debug, Serialize)]
struct MyInvitesResponse {
    remaining_invites: i32,
    total_invites: i32,
    used_invites: i32,
    invites: Vec<InviteRecord>,
}

/// Check if user is registered
async fn check_user(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CheckUserQuery>,
) -> Result<Json<CheckUserResponse>, StatusCode> {
    // Check if invites are enabled
    let invites_enabled: bool = sqlx::query_scalar(
        "SELECT value = 'true' FROM invite_settings WHERE key = 'invites_enabled'"
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to check invite settings: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(true);

    // Check if user is registered
    let registered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM registered_users WHERE account_id = $1)"
    )
    .bind(&query.account_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to check user registration: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(CheckUserResponse { registered, invites_enabled }))
}

/// Access check result
enum AccessCheck {
    Allowed,
    NotRegistered,
    Blacklisted(String),
}

/// Check if account can access email service (registered + not blacklisted)
/// Returns AccessCheck enum with reason if denied
async fn check_account_access(db: &PgPool, account_id: &str) -> Result<AccessCheck, StatusCode> {
    // Check if invites are enabled (if disabled, everyone has access)
    let invites_enabled: bool = sqlx::query_scalar(
        "SELECT value = 'true' FROM invite_settings WHERE key = 'invites_enabled'"
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        error!("Failed to check invite settings: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(true);

    // Check if account is blacklisted (always check, even if invites disabled)
    // reason column is nullable, so we get Option<Option<String>> from fetch_optional
    let blacklist_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM blacklist WHERE account_id = $1)"
    )
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|e| {
        error!("Failed to check blacklist: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if blacklist_exists {
        // Get the reason if exists
        let reason: Option<String> = sqlx::query_scalar(
            "SELECT reason FROM blacklist WHERE account_id = $1"
        )
        .bind(account_id)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            error!("Failed to get blacklist reason: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .flatten(); // Option<Option<String>> -> Option<String>

        return Ok(AccessCheck::Blacklisted(reason.unwrap_or_else(|| "Account suspended".to_string())));
    }

    // If invites disabled, everyone (except blacklisted) has access
    if !invites_enabled {
        return Ok(AccessCheck::Allowed);
    }

    // Check registration
    let registered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM registered_users WHERE account_id = $1)"
    )
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|e| {
        error!("Failed to check registration: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !registered {
        return Ok(AccessCheck::NotRegistered);
    }

    Ok(AccessCheck::Allowed)
}

/// Increment email stats for received email
async fn increment_received_stats(db: &PgPool, account_id: &str) {
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO email_stats (account_id, emails_received, last_received_at)
        VALUES ($1, 1, NOW())
        ON CONFLICT (account_id) DO UPDATE SET
            emails_received = email_stats.emails_received + 1,
            last_received_at = NOW()
        "#
    )
    .bind(account_id)
    .execute(db)
    .await {
        warn!("Failed to update received stats for {}: {}", account_id, e);
    }
}

/// Increment email stats for sent email
async fn increment_sent_stats(db: &PgPool, account_id: &str) {
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO email_stats (account_id, emails_sent, last_sent_at)
        VALUES ($1, 1, NOW())
        ON CONFLICT (account_id) DO UPDATE SET
            emails_sent = email_stats.emails_sent + 1,
            last_sent_at = NOW()
        "#
    )
    .bind(account_id)
    .execute(db)
    .await {
        warn!("Failed to update sent stats for {}: {}", account_id, e);
    }
}

/// Use an invite code to register
async fn use_invite(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UseInviteBody>,
) -> Result<Json<UseInviteResponse>, StatusCode> {
    // Rate limiting: 10 attempts per minute per IP
    let ip = addr.ip().to_string();
    {
        let mut limiter = state.invite_rate_limiter.lock().await;
        let now = Utc::now();
        let window_duration = chrono::Duration::minutes(1);

        if let Some((count, window_start)) = limiter.get_mut(&ip) {
            if now.signed_duration_since(*window_start) > window_duration {
                // Window expired, reset
                *count = 1;
                *window_start = now;
            } else if *count >= 10 {
                // Rate limited
                warn!("Rate limit exceeded for IP {} on /invites/use", ip);
                return Ok(Json(UseInviteResponse {
                    success: false,
                    error: Some("Too many attempts. Please try again in a minute.".to_string()),
                }));
            } else {
                *count += 1;
            }
        } else {
            limiter.insert(ip.clone(), (1, now));
        }

        // Cleanup old entries (keep map from growing indefinitely)
        if limiter.len() > 10000 {
            let cutoff = now - window_duration;
            limiter.retain(|_, (_, start)| *start > cutoff);
        }
    }

    let code = body.code.trim().to_uppercase();

    // Check if user already registered
    let already_registered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM registered_users WHERE account_id = $1)"
    )
    .bind(&body.account_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if already_registered {
        return Ok(Json(UseInviteResponse {
            success: false,
            error: Some("You are already registered".to_string()),
        }));
    }

    // Find valid invite code (not used, not expired)
    let invite: Option<(Uuid, String)> = sqlx::query_as(
        r#"
        SELECT id, owner_account_id
        FROM invites
        WHERE code = $1
          AND used_by_account_id IS NULL
          AND expires_at > NOW()
        "#
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to find invite: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some((invite_id, inviter)) = invite else {
        return Ok(Json(UseInviteResponse {
            success: false,
            error: Some("Invalid or expired invite code".to_string()),
        }));
    };

    // Start transaction
    let mut tx = state.db.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Mark invite as used
    sqlx::query(
        "UPDATE invites SET used_by_account_id = $1, used_at = NOW() WHERE id = $2"
    )
    .bind(&body.account_id)
    .bind(invite_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Register user
    sqlx::query(
        r#"
        INSERT INTO registered_users (account_id, invited_by, invite_code)
        VALUES ($1, $2, $3)
        "#
    )
    .bind(&body.account_id)
    .bind(&inviter)
    .bind(&code)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create invite allowance for new user
    let default_invites: i32 = sqlx::query_scalar(
        "SELECT COALESCE(value::int, 3) FROM invite_settings WHERE key = 'default_base_invites'"
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(3);

    sqlx::query(
        "INSERT INTO invite_allowance (account_id, base_invites) VALUES ($1, $2)"
    )
    .bind(&body.account_id)
    .bind(default_invites)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Referral bonus: give inviter +1 invite when their invitee registers
    sqlx::query(
        r#"
        UPDATE invite_allowance
        SET bonus_invites = bonus_invites + 1
        WHERE account_id = $1
        "#
    )
    .bind(&inviter)
    .execute(&mut *tx)
    .await
    .ok(); // Don't fail if inviter doesn't have allowance row

    tx.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!("User {} registered using invite {} from {}", body.account_id, code, inviter);

    // Send notification email to inviter (async, don't block registration)
    let inviter_clone = inviter.clone();
    let new_user = body.account_id.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = send_invite_accepted_notification(&state_clone, &inviter_clone, &new_user).await {
            warn!("Failed to send invite notification to {}: {}", inviter_clone, e);
        }
    });

    Ok(Json(UseInviteResponse { success: true, error: None }))
}

/// Send notification email to inviter when their invite is accepted
async fn send_invite_accepted_notification(
    state: &Arc<AppState>,
    inviter: &str,
    new_user: &str,
) -> Result<(), String> {
    // Build inviter's email address
    let inviter_local = inviter
        .strip_suffix(&state.account_suffix)
        .unwrap_or(inviter);
    let inviter_email = format!("{}@{}", inviter_local, state.email_domain);

    let new_user_local = new_user
        .strip_suffix(&state.account_suffix)
        .unwrap_or(new_user);

    let subject = format!("{} joined near.email using your invite!", new_user_local);

    let email_body = format!(
        r#"Great news!

{} has joined near.email using your invite code.

As a thank you, you've received +1 bonus invite!

Your new friend's email: {}@{}

Keep spreading the word and earn more invites when your friends join.

--
near.email team"#,
        new_user, new_user_local, state.email_domain
    );

    // Send via existing send_email logic
    let send_body = SendEmailBody {
        from_account: format!("dev{}", state.account_suffix), // dev.near or dev.testnet
        to: inviter_email,
        subject,
        body: email_body,
        attachments: vec![],
    };

    let result = send_email(State(state.clone()), Json(send_body)).await
        .map_err(|e| format!("HTTP error: {:?}", e))?;

    if !result.0.success {
        return Err(result.0.error.unwrap_or_else(|| "Unknown error".to_string()));
    }

    info!("Sent invite acceptance notification to {}", inviter);
    Ok(())
}

/// Internal: Generate invite without signature verification (for internal use)
async fn generate_invite_internal(
    db: &PgPool,
    account_id: &str,
) -> Result<GenerateInviteResponse, StatusCode> {
    // Check remaining invites
    let (base, bonus, used): (i32, i32, i64) = {
        let allowance: Option<(i32, i32)> = sqlx::query_as(
            "SELECT base_invites, bonus_invites FROM invite_allowance WHERE account_id = $1"
        )
        .bind(account_id)
        .fetch_optional(db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let (base, bonus) = allowance.unwrap_or((0, 0));

        let used: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invites WHERE owner_account_id = $1"
        )
        .bind(account_id)
        .fetch_one(db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        (base, bonus, used)
    };

    let remaining = (base + bonus) as i64 - used;
    if remaining <= 0 {
        return Ok(GenerateInviteResponse {
            success: false,
            code: None,
            expires_at: None,
            error: Some("No invites remaining".to_string()),
        });
    }

    // Get expiry days
    let expiry_days: i32 = sqlx::query_scalar(
        "SELECT COALESCE(value::int, 7) FROM invite_settings WHERE key = 'invite_expiry_days'"
    )
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(7);

    // Generate unique code
    let code = generate_invite_code();
    let expires_at = chrono::Utc::now() + chrono::Duration::days(expiry_days as i64);

    sqlx::query(
        r#"
        INSERT INTO invites (code, owner_account_id, expires_at)
        VALUES ($1, $2, $3)
        "#
    )
    .bind(&code)
    .bind(account_id)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|e| {
        error!("Failed to create invite: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Invite {} generated by {}", code, account_id);

    Ok(GenerateInviteResponse {
        success: true,
        code: Some(code),
        expires_at: Some(expires_at.to_rfc3339()),
        error: None,
    })
}

/// Generate a new invite code (requires signature)
async fn generate_invite(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateInviteBody>,
) -> Result<Json<GenerateInviteResponse>, StatusCode> {
    // Verify signature with public key ownership check
    let signed = SignedRequest {
        account_id: body.account_id.clone(),
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        timestamp_ms: body.timestamp_ms,
        nonce: body.nonce.clone(),
    };
    if let Err(e) = verify_signature_with_ownership(&state.fastnear_api_url, state.near_rpc_url.as_deref(), &signed, "generate_invite").await {
        warn!("Signature verification failed for generate_invite: {}", e);
        return Ok(Json(GenerateInviteResponse {
            success: false,
            code: None,
            expires_at: None,
            error: Some(format!("Authentication failed: {}", e)),
        }));
    }

    let result = generate_invite_internal(&state.db, &body.account_id).await?;
    Ok(Json(result))
}

/// Send an invite via email
async fn send_invite_email(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SendInviteBody>,
) -> Result<Json<SendInviteResponse>, StatusCode> {
    // Verify signature with public key ownership check
    let signed = SignedRequest {
        account_id: body.account_id.clone(),
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        timestamp_ms: body.timestamp_ms,
        nonce: body.nonce.clone(),
    };
    if let Err(e) = verify_signature_with_ownership(&state.fastnear_api_url, state.near_rpc_url.as_deref(), &signed, "send_invite").await {
        warn!("Signature verification failed for send_invite_email: {}", e);
        return Ok(Json(SendInviteResponse {
            success: false,
            code: None,
            error: Some(format!("Authentication failed: {}", e)),
        }));
    }

    // Generate an invite using internal function (signature already verified above)
    let gen_response = generate_invite_internal(&state.db, &body.account_id).await?;
    if !gen_response.success {
        return Ok(Json(SendInviteResponse {
            success: false,
            code: None,
            error: gen_response.error,
        }));
    }

    let code = gen_response.code.unwrap();
    let expires_at = gen_response.expires_at.unwrap();

    // Update invite with recipient email
    sqlx::query(
        "UPDATE invites SET recipient_email = $1 WHERE code = $2"
    )
    .bind(&body.recipient_email)
    .bind(&code)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build email - strip suffix from account
    let from_local = body.account_id
        .strip_suffix(&state.account_suffix)
        .unwrap_or(&body.account_id);

    let subject = format!("{} invites you to near.email", from_local);
    let invite_link = format!("https://near.email?invite={}", code);

    let email_body = format!(
        r#"Hi!

{} has invited you to join near.email - blockchain-native secure email.

Your invite code: {}

Or click this link to get started:
{}

This invite expires on {}.

What is near.email?
- Your NEAR wallet = your email (alice.near -> alice@near.email)
- End-to-end encrypted - only you can read your mail
- Send to anyone - Gmail, Outlook, any address works
- Powered by TEE (Trusted Execution Environment) for maximum security

Get started at https://near.email

--
Sent via near.email"#,
        from_local, code, invite_link, expires_at
    );

    // Send the email using existing send_email logic
    let send_body = SendEmailBody {
        from_account: body.account_id.clone(),
        to: body.recipient_email.clone(),
        subject,
        body: email_body,
        attachments: vec![],
    };

    let send_result = send_email(State(state), Json(send_body)).await?;

    if !send_result.0.success {
        return Ok(Json(SendInviteResponse {
            success: false,
            code: Some(code),
            error: send_result.0.error,
        }));
    }

    info!("Invite {} sent to {} by {}", code, body.recipient_email, body.account_id);

    Ok(Json(SendInviteResponse {
        success: true,
        code: Some(code),
        error: None,
    }))
}

/// Get user's invites and status (requires signature)
async fn my_invites(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MyInvitesBody>,
) -> Result<Json<MyInvitesResponse>, StatusCode> {
    // Verify signature with public key ownership check
    let signed = SignedRequest {
        account_id: body.account_id.clone(),
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        timestamp_ms: body.timestamp_ms,
        nonce: body.nonce.clone(),
    };
    if let Err(e) = verify_signature_with_ownership(&state.fastnear_api_url, state.near_rpc_url.as_deref(), &signed, "my_invites").await {
        warn!("Signature verification failed for my_invites: {}", e);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Get allowance
    let allowance: Option<(i32, i32)> = sqlx::query_as(
        "SELECT base_invites, bonus_invites FROM invite_allowance WHERE account_id = $1"
    )
    .bind(&body.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (base, bonus) = allowance.unwrap_or((0, 0));
    let total_invites = base + bonus;

    // Get all invites created by user
    let rows: Vec<InviteRow> = sqlx::query_as(
        r#"
        SELECT id, code, recipient_email, used_by_account_id, used_at, created_at, expires_at
        FROM invites
        WHERE owner_account_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(&body.account_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let used_invites = rows.len() as i32;
    let remaining_invites = total_invites - used_invites;

    let now = chrono::Utc::now();
    let invites: Vec<InviteRecord> = rows
        .into_iter()
        .map(|row| {
            let status = if row.used_by_account_id.is_some() {
                "used".to_string()
            } else if row.expires_at < now {
                "expired".to_string()
            } else {
                "pending".to_string()
            };

            InviteRecord {
                id: row.id.to_string(),
                code: row.code,
                recipient_email: row.recipient_email,
                used_by: row.used_by_account_id,
                used_at: row.used_at.map(|t| t.to_rfc3339()),
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                status,
            }
        })
        .collect();

    Ok(Json(MyInvitesResponse {
        remaining_invites,
        total_invites,
        used_invites,
        invites,
    }))
}

/// Admin: Grant bonus invites to a user
#[derive(Debug, Deserialize)]
struct GrantInvitesBody {
    account_id: String,
    amount: i32,
}

#[derive(Debug, Serialize)]
struct GrantInvitesResponse {
    success: bool,
    new_bonus: i32,
}

async fn admin_grant_invites(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GrantInvitesBody>,
) -> Result<Json<GrantInvitesResponse>, StatusCode> {
    // Upsert invite_allowance
    let new_bonus: i32 = sqlx::query_scalar(
        r#"
        INSERT INTO invite_allowance (account_id, bonus_invites)
        VALUES ($1, $2)
        ON CONFLICT (account_id) DO UPDATE SET bonus_invites = invite_allowance.bonus_invites + $2
        RETURNING bonus_invites
        "#
    )
    .bind(&body.account_id)
    .bind(body.amount)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to grant invites: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Admin granted {} invites to {}, new bonus: {}", body.amount, body.account_id, new_bonus);

    Ok(Json(GrantInvitesResponse {
        success: true,
        new_bonus,
    }))
}

/// Admin: Register a seed user (without invite)
#[derive(Debug, Deserialize)]
struct SeedUserBody {
    account_id: String,
    base_invites: Option<i32>,
}

// ==================== Blacklist Types ====================

#[derive(Debug, Deserialize)]
struct BlacklistAddBody {
    account_id: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlacklistRemoveBody {
    account_id: String,
}

#[derive(Debug, Deserialize)]
struct BlacklistCheckQuery {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct BlacklistResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BlacklistCheckResponse {
    blacklisted: bool,
    reason: Option<String>,
}

// ==================== Stats Types ====================

#[derive(Debug, Deserialize)]
struct GetStatsQuery {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    account_id: String,
    emails_received: i32,
    emails_sent: i32,
    last_received_at: Option<String>,
    last_sent_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedUserResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn admin_seed_user(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SeedUserBody>,
) -> Result<Json<SeedUserResponse>, StatusCode> {
    let base_invites = body.base_invites.unwrap_or(3);

    // Check if already registered
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM registered_users WHERE account_id = $1)"
    )
    .bind(&body.account_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if exists {
        return Ok(Json(SeedUserResponse {
            success: false,
            error: Some("User already registered".to_string()),
        }));
    }

    let mut tx = state.db.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Register as seed user (no inviter)
    sqlx::query(
        "INSERT INTO registered_users (account_id) VALUES ($1)"
    )
    .bind(&body.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create allowance
    sqlx::query(
        "INSERT INTO invite_allowance (account_id, base_invites) VALUES ($1, $2)"
    )
    .bind(&body.account_id)
    .bind(base_invites)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!("Seed user {} registered with {} invites", body.account_id, base_invites);

    Ok(Json(SeedUserResponse { success: true, error: None }))
}

// ==================== Blacklist Admin Handlers ====================

/// Admin: Add account to blacklist
async fn admin_blacklist_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BlacklistAddBody>,
) -> Result<Json<BlacklistResponse>, StatusCode> {
    let result = sqlx::query(
        r#"
        INSERT INTO blacklist (account_id, reason)
        VALUES ($1, $2)
        ON CONFLICT (account_id) DO UPDATE SET reason = $2
        "#
    )
    .bind(&body.account_id)
    .bind(&body.reason)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!("Account {} added to blacklist: {:?}", body.account_id, body.reason);
            Ok(Json(BlacklistResponse { success: true, error: None }))
        }
        Err(e) => {
            error!("Failed to add to blacklist: {}", e);
            Ok(Json(BlacklistResponse {
                success: false,
                error: Some(format!("Database error: {}", e)),
            }))
        }
    }
}

/// Admin: Remove account from blacklist
async fn admin_blacklist_remove(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BlacklistRemoveBody>,
) -> Result<Json<BlacklistResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM blacklist WHERE account_id = $1")
        .bind(&body.account_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() > 0 {
                info!("Account {} removed from blacklist", body.account_id);
                Ok(Json(BlacklistResponse { success: true, error: None }))
            } else {
                Ok(Json(BlacklistResponse {
                    success: false,
                    error: Some("Account not found in blacklist".to_string()),
                }))
            }
        }
        Err(e) => {
            error!("Failed to remove from blacklist: {}", e);
            Ok(Json(BlacklistResponse {
                success: false,
                error: Some(format!("Database error: {}", e)),
            }))
        }
    }
}

/// Admin: Check if account is blacklisted
async fn admin_blacklist_check(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BlacklistCheckQuery>,
) -> Result<Json<BlacklistCheckResponse>, StatusCode> {
    let result: Option<Option<String>> = sqlx::query_scalar(
        "SELECT reason FROM blacklist WHERE account_id = $1"
    )
    .bind(&query.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to check blacklist: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match result {
        Some(reason) => Ok(Json(BlacklistCheckResponse {
            blacklisted: true,
            reason,
        })),
        None => Ok(Json(BlacklistCheckResponse {
            blacklisted: false,
            reason: None,
        })),
    }
}

/// Admin: Get email stats for an account
async fn admin_get_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetStatsQuery>,
) -> Result<Json<StatsResponse>, StatusCode> {
    let result: Option<(i32, i32, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT emails_received, emails_sent, last_received_at, last_sent_at
        FROM email_stats
        WHERE account_id = $1
        "#
    )
    .bind(&query.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to get stats: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match result {
        Some((received, sent, last_received, last_sent)) => Ok(Json(StatsResponse {
            account_id: query.account_id,
            emails_received: received,
            emails_sent: sent,
            last_received_at: last_received.map(|t| t.to_rfc3339()),
            last_sent_at: last_sent.map(|t| t.to_rfc3339()),
        })),
        None => Ok(Json(StatsResponse {
            account_id: query.account_id,
            emails_received: 0,
            emails_sent: 0,
            last_received_at: None,
            last_sent_at: None,
        })),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Test NEAR RPC fallback for public key ownership verification
    #[tokio::test]
    async fn test_verify_access_key_owner_via_rpc_testnet() {
        // Known testnet account with known public key
        let public_key = "ed25519:2a7mj4kDQvr6HfJpJa7W5bg1K2B9GsLNYXBa4um5S7MB";
        let account_id = "zavodil.testnet";

        // None = auto-detect RPC based on account suffix
        let result = verify_access_key_owner_via_rpc(None, public_key, account_id).await;
        assert!(result.is_ok(), "Expected key to belong to account: {:?}", result);
    }

    #[tokio::test]
    async fn test_verify_access_key_owner_via_rpc_wrong_account() {
        // Key belongs to zavodil.testnet, not to nonexistent.testnet
        let public_key = "ed25519:2a7mj4kDQvr6HfJpJa7W5bg1K2B9GsLNYXBa4um5S7MB";
        let account_id = "nonexistent-account-12345.testnet";

        let result = verify_access_key_owner_via_rpc(None, public_key, account_id).await;
        assert!(result.is_err(), "Expected key NOT to belong to wrong account");
    }

    #[tokio::test]
    async fn test_verify_access_key_owner_with_fastnear_fallback() {
        // This key is not indexed by FastNEAR testnet, should fall back to RPC
        let fastnear_url = "https://test.api.fastnear.com";
        let public_key = "ed25519:2a7mj4kDQvr6HfJpJa7W5bg1K2B9GsLNYXBa4um5S7MB";
        let account_id = "zavodil.testnet";

        // None = auto-detect RPC based on account suffix
        let result = verify_access_key_owner(fastnear_url, None, public_key, account_id).await;
        assert!(result.is_ok(), "Expected fallback to RPC to work: {:?}", result);
    }

    /// Test NEP-413 payload serialization matches expected format
    #[test]
    fn test_nep413_payload_serialization() {
        let nonce = [0u8; 32]; // Zero nonce for deterministic test
        let payload = Nep413Payload {
            message: "near.email:my_invites:test.testnet:1706300000000".to_string(),
            nonce,
            recipient: "near.email".to_string(),
            callback_url: None,
        };

        let bytes = borsh::to_vec(&payload).expect("Failed to serialize");
        // Verify it serializes without error and has reasonable length
        assert!(bytes.len() > 50, "Payload should be >50 bytes");
        assert!(bytes.len() < 200, "Payload should be <200 bytes");
    }

    /// Test NEP-413 tag constant
    #[test]
    fn test_nep413_tag() {
        // NEP-413 tag is 2^31 + 413
        assert_eq!(NEP413_TAG, 2147484061);
        assert_eq!(NEP413_TAG, (1u32 << 31) + 413);
    }
}

