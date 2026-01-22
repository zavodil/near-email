//! SMTP Server for near.email
//!
//! Receives emails for *@near.email addresses, encrypts them using
//! BIP32-style derived public keys, and stores in PostgreSQL.
//!
//! The master private key is never touched by this server - only the public key
//! is used for derivation. Decryption happens in OutLayer TEE.

mod crypto;
mod db;
mod handler;

use anyhow::Result;
use mailin_embedded::{Server, SslConfig};
use sqlx::postgres::PgPoolOptions;
use std::env;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment
    dotenvy::dotenv().ok();

    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load config
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let master_pubkey_hex = env::var("MASTER_PUBLIC_KEY")
        .expect("MASTER_PUBLIC_KEY must be set");
    let smtp_host = env::var("SMTP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let smtp_port: u16 = env::var("SMTP_PORT")
        .unwrap_or_else(|_| "25".to_string())
        .parse()
        .expect("SMTP_PORT must be a valid port number");
    let email_domain = env::var("EMAIL_DOMAIN").unwrap_or_else(|_| "near.email".to_string());
    let default_account_suffix = env::var("DEFAULT_ACCOUNT_SUFFIX")
        .unwrap_or_else(|_| ".near".to_string());

    // Parse master public key
    let master_pubkey = crypto::parse_public_key(&master_pubkey_hex)
        .expect("Invalid MASTER_PUBLIC_KEY");

    info!("Master public key loaded (default suffix: {})", default_account_suffix);

    // Connect to database
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    info!("Connected to database");

    // Run migrations
    db::run_migrations(&db_pool).await?;

    // Create handler
    let handler = handler::NearEmailHandler::new(
        db_pool,
        master_pubkey,
        email_domain,
        default_account_suffix,
    );

    // Start SMTP server
    let addr = format!("{}:{}", smtp_host, smtp_port);
    info!("Starting SMTP server on {}", addr);

    let mut server = Server::new(handler);
    server.with_name("near.email");
    server.with_ssl(SslConfig::None).map_err(|e| anyhow::anyhow!("SSL config error: {}", e))?;
    server.with_addr(&addr).map_err(|e| anyhow::anyhow!("Address config error: {}", e))?;

    server.serve().map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}
