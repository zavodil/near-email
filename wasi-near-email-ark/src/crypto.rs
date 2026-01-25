//! Cryptographic utilities for near.email WASI module
//!
//! Implements private key derivation and email decryption.
//!
//! Uses pure Rust crypto libraries for WASI compatibility:
//! - libsecp256k1 (not secp256k1 which has C bindings)
//! - ECDH + ChaCha20-Poly1305 for encryption (EC01 format)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use libsecp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Magic bytes for ECDH + ChaCha20 format (current)
const ECDH_MAGIC: &[u8; 4] = b"EC01";

/// Domain separation prefix for key derivation
const DERIVATION_PREFIX: &[u8] = b"near-email:v1:";

/// Parse a hex-encoded private key
pub fn parse_private_key(hex_str: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    let privkey = SecretKey::parse_slice(&bytes)
        .map_err(|e| format!("Invalid private key: {:?}", e))?;
    Ok(privkey)
}

/// Derive master public key from master private key
/// Returns compressed public key in hex format (33 bytes = 66 hex chars)
pub fn get_master_pubkey(master_privkey: &SecretKey) -> String {
    let pubkey = PublicKey::from_secret_key(master_privkey);
    hex::encode(pubkey.serialize_compressed())
}

/// Derive a user-specific private key from master private key
///
/// Uses additive key derivation:
///   user_privkey = master_privkey + SHA256(prefix + account_id)
///
/// This must match the public key derivation used by SMTP server.
pub fn derive_user_privkey(
    master_privkey: &SecretKey,
    account_id: &str,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    // Create deterministic tweak from account_id
    let mut hasher = Sha256::new();
    hasher.update(DERIVATION_PREFIX);
    hasher.update(account_id.as_bytes());
    let tweak_bytes: [u8; 32] = hasher.finalize().into();

    // Convert tweak to SecretKey (which is a scalar)
    let tweak = SecretKey::parse_slice(&tweak_bytes)
        .map_err(|e| format!("Failed to create tweak: {:?}", e))?;

    // Add tweak to private key (scalar addition)
    let mut user_privkey = master_privkey.clone();
    user_privkey.tweak_add_assign(&tweak)
        .map_err(|e| format!("Failed to derive private key: {:?}", e))?;

    Ok(user_privkey)
}

/// Decrypt email data
///
/// Supports formats:
/// 1. EC01: ECDH + ChaCha20-Poly1305 (current, from frontend and internal)
/// 2. Legacy ECIES: For inbox emails from smtp-server (Rust ecies crate)
///
/// EC01 format:
/// - Magic: "EC01" (4 bytes)
/// - Ephemeral public key: 33 bytes (compressed)
/// - Nonce: 12 bytes
/// - ChaCha20-Poly1305 ciphertext + tag: remaining bytes
pub fn decrypt_email(
    user_privkey: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Check for EC01 format (ECDH + ChaCha20)
    if encrypted.len() > 4 && &encrypted[0..4] == ECDH_MAGIC {
        return decrypt_ecdh(user_privkey, encrypted);
    }

    // Fallback to legacy ECIES (for inbox from smtp-server)
    let decrypted = ecies::decrypt(&user_privkey.serialize(), encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(decrypted)
}

/// Decrypt data using ECDH + ChaCha20-Poly1305 (EC01 format)
///
/// Format: EC01 (4) || ephemeral_pubkey (33) || nonce (12) || ciphertext+tag
fn decrypt_ecdh(
    user_privkey: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const HEADER_SIZE: usize = 4;       // EC01
    const PUBKEY_SIZE: usize = 33;      // compressed pubkey
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;         // Poly1305 tag
    const MIN_SIZE: usize = HEADER_SIZE + PUBKEY_SIZE + NONCE_SIZE + TAG_SIZE;

    if encrypted.len() < MIN_SIZE {
        return Err(format!(
            "EC01 data too short: {} bytes, need at least {}",
            encrypted.len(), MIN_SIZE
        ).into());
    }

    // Parse ephemeral public key
    let ephemeral_pubkey_bytes = &encrypted[HEADER_SIZE..HEADER_SIZE + PUBKEY_SIZE];
    let mut shared_point = PublicKey::parse_slice(ephemeral_pubkey_bytes, None)
        .map_err(|e| format!("Invalid ephemeral pubkey: {:?}", e))?;

    // ECDH: shared_point = ephemeral_pubkey * user_privkey
    shared_point.tweak_mul_assign(user_privkey)
        .map_err(|e| format!("ECDH failed: {:?}", e))?;

    // Extract x-coordinate (skip prefix byte from compressed pubkey)
    let shared_compressed = shared_point.serialize_compressed();
    let shared_x = &shared_compressed[1..];

    // Derive key: SHA256(x-coordinate)
    let key: [u8; 32] = Sha256::digest(shared_x).into();

    // Extract nonce and ciphertext
    let nonce_start = HEADER_SIZE + PUBKEY_SIZE;
    let nonce_bytes = &encrypted[nonce_start..nonce_start + NONCE_SIZE];
    let ciphertext = &encrypted[nonce_start + NONCE_SIZE..];

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("ChaCha20-Poly1305 decryption failed: {:?}", e))?;

    Ok(decrypted)
}

/// Derive user's public key from master private key
/// Used for encrypting emails to other NEAR accounts
pub fn derive_user_pubkey(
    master_privkey: &SecretKey,
    account_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let user_privkey = derive_user_privkey(master_privkey, account_id)?;
    let pubkey = PublicKey::from_secret_key(&user_privkey);
    Ok(pubkey.serialize_compressed().to_vec())
}

/// Encrypt data for a specific NEAR account using ECDH + ChaCha20-Poly1305
/// Used for internal email sending (NEAR to NEAR) and sent folder
///
/// Format: EC01 || ephemeral_pubkey (33 bytes) || nonce (12 bytes) || ciphertext+tag
pub fn encrypt_for_account(
    master_privkey: &SecretKey,
    account_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rand::RngCore;

    let user_pubkey_bytes = derive_user_pubkey(master_privkey, account_id)?;
    let user_pubkey = PublicKey::parse_slice(&user_pubkey_bytes, None)
        .map_err(|e| format!("Invalid user pubkey: {:?}", e))?;

    // Generate ephemeral keypair
    let mut ephemeral_privkey_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_privkey_bytes);
    let ephemeral_privkey = SecretKey::parse_slice(&ephemeral_privkey_bytes)
        .map_err(|e| format!("Failed to create ephemeral key: {:?}", e))?;
    let ephemeral_pubkey = PublicKey::from_secret_key(&ephemeral_privkey);

    // ECDH: shared_point = user_pubkey * ephemeral_privkey
    let mut shared_point = user_pubkey.clone();
    shared_point.tweak_mul_assign(&ephemeral_privkey)
        .map_err(|e| format!("ECDH failed: {:?}", e))?;

    // Extract x-coordinate (skip prefix byte from compressed pubkey)
    let shared_x = &shared_point.serialize_compressed()[1..];

    // Derive key: SHA256(x-coordinate)
    let key: [u8; 32] = Sha256::digest(shared_x).into();

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {:?}", e))?;

    // Build output: EC01 || ephemeral_pubkey || nonce || ciphertext
    let ephemeral_pubkey_compressed = ephemeral_pubkey.serialize_compressed();
    let mut output = Vec::with_capacity(4 + 33 + 12 + ciphertext.len());
    output.extend_from_slice(ECDH_MAGIC);
    output.extend_from_slice(&ephemeral_pubkey_compressed);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}
