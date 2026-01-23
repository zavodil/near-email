//! Database HTTP API for near.email WASI module
//!
//! Provides REST endpoints for the WASI module to access the database,
//! since WASI cannot make direct database connections.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use hickory_resolver::{config::*, TokioAsyncResolver};
use std::net::IpAddr;
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{
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
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

/// DKIM configuration for signing outgoing emails
struct DkimConfig {
    /// RSA private key PEM for signing
    private_key_pem: String,
    /// Domain to sign for (e.g., "near.email")
    domain: String,
    /// Selector (e.g., "mail" for mail._domainkey.near.email)
    selector: String,
}

struct AppState {
    db: PgPool,
    email_domain: String,
    /// Account suffix to strip from account_id for email (e.g., ".testnet" or ".near")
    account_suffix: String,
    resolver: TokioAsyncResolver,
    dkim: Option<DkimConfig>,
    /// Email signature template (use {account} placeholder for sender's NEAR account)
    /// Example: "Sent by {account} via NEAR OutLayer"
    email_signature: Option<String>,
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

    // Email signature template - use {account} for sender's NEAR account
    // Example: "Sent by {account} via NEAR OutLayer"
    let email_signature = env::var("EMAIL_SIGNATURE").ok().filter(|s| !s.is_empty());
    if let Some(ref sig) = email_signature {
        info!("Email signature enabled: {}", sig);
    }

    info!("Email domain: {}, account suffix: {}", email_domain, account_suffix);

    let state = AppState { db, email_domain, account_suffix, resolver, dkim, email_signature };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/emails", get(get_emails))
        .route("/emails/count", get(count_emails))
        .route("/emails/:id", delete(delete_email))
        .route("/send", post(send_email))
        .route("/internal-store", post(store_internal_email))
        .route("/health", get(health))
        .layer(cors)
        .with_state(Arc::new(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting DB API on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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

#[derive(Debug, Deserialize)]
struct SendEmailBody {
    from_account: String,
    to: String,
    subject: String,
    body: String,
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

    // Build email body with optional signature
    let email_body = if let Some(ref sig_template) = state.email_signature {
        let signature = sig_template.replace("{account}", &body.from_account);
        format!("{}\n\n--\n{}", body.body, signature)
    } else {
        body.body.clone()
    };

    // Build email message
    let email = Message::builder()
        .from(from_mailbox.clone())
        .to(to_mailbox.clone())
        .subject(&body.subject)
        .message_id(Some(message_id))
        .header(ContentType::TEXT_PLAIN)
        .body(email_body)
        .map_err(|e| {
            error!("Failed to build email: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

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
    let send_result = if let Some(dkim) = &state.dkim {
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
    };

    match send_result {
        Ok(_) => {
            info!("Email sent successfully to {} via {}", body.to, mx_host);
            Ok(Json(SendResponse { success: true, error: None }))
        }
        Err(e) => {
            error!("Failed to send email to {} via {}: {}", body.to, mx_host, e);
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

    Ok(Json(StoreInternalResponse {
        success: true,
        id: id.to_string(),
    }))
}
