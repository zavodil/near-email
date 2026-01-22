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
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: PgPool,
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

    let state = AppState { db };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/emails", get(get_emails))
        .route("/emails/count", get(count_emails))
        .route("/emails/:id", delete(delete_email))
        .route("/send", post(send_email))
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
    Json(body): Json<SendEmailBody>,
) -> Result<Json<SendResponse>, StatusCode> {
    // TODO: Implement SMTP sending
    // For now, just log and return success
    info!(
        "Send email request: from={}, to={}, subject={}",
        body.from_account, body.to, body.subject
    );

    Ok(Json(SendResponse { success: true }))
}
