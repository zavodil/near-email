//! Cryptographic utilities for near.email WASI module
//!
//! Implements private key derivation and email decryption.
//!
//! Uses pure Rust crypto libraries for WASI compatibility:
//! - libsecp256k1 (not secp256k1 which has C bindings)
//! - Hybrid encryption: ECIES for key + ChaCha20-Poly1305 for data

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use libsecp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Magic bytes for hybrid encryption format v1
const HYBRID_MAGIC: &[u8; 4] = b"HE01";

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
    // Clone master and add tweak to it
    let mut user_privkey = master_privkey.clone();
    user_privkey.tweak_add_assign(&tweak)
        .map_err(|e| format!("Failed to derive private key: {:?}", e))?;

    Ok(user_privkey)
}

/// Decrypt email data
///
/// Supports two formats:
/// 1. Hybrid (HE01): ECIES-encrypted 32-byte key + ChaCha20-Poly1305 encrypted data
/// 2. Legacy ECIES: Pure ECIES encryption (for backward compatibility)
///
/// Hybrid format (HE01):
/// - Magic: "HE01" (4 bytes)
/// - Key blob length: 2 bytes (little-endian u16)
/// - ECIES encrypted symmetric key: key_blob_length bytes
/// - Nonce: 12 bytes
/// - ChaCha20-Poly1305 ciphertext + tag: remaining bytes
pub fn decrypt_email(
    user_privkey: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Check for hybrid format magic
    if encrypted.len() > 4 && &encrypted[0..4] == HYBRID_MAGIC {
        return decrypt_hybrid(user_privkey, encrypted);
    }

    // Fallback to legacy ECIES
    let decrypted = ecies::decrypt(&user_privkey.serialize(), encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(decrypted)
}

/// Decrypt data using hybrid encryption (ECIES key + ChaCha20-Poly1305 data)
fn decrypt_hybrid(
    user_privkey: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Parse header
    if encrypted.len() < 4 + 2 + 12 + 16 {
        return Err("Hybrid encrypted data too short".into());
    }

    // Skip magic (4 bytes), read key blob length (2 bytes)
    let key_len = u16::from_le_bytes([encrypted[4], encrypted[5]]) as usize;

    let header_size = 4 + 2; // magic + key_len
    let nonce_size = 12;
    let min_size = header_size + key_len + nonce_size + 16; // +16 for tag

    if encrypted.len() < min_size {
        return Err(format!(
            "Hybrid data too short: {} bytes, need at least {}",
            encrypted.len(),
            min_size
        ).into());
    }

    // Extract ECIES-encrypted symmetric key
    let key_blob = &encrypted[header_size..header_size + key_len];

    // Decrypt symmetric key using ECIES
    let symmetric_key = ecies::decrypt(&user_privkey.serialize(), key_blob)
        .map_err(|e| format!("Failed to decrypt symmetric key: {}", e))?;

    if symmetric_key.len() != 32 {
        return Err(format!(
            "Invalid symmetric key length: {} (expected 32)",
            symmetric_key.len()
        ).into());
    }

    // Extract nonce and ciphertext
    let nonce_start = header_size + key_len;
    let nonce_bytes = &encrypted[nonce_start..nonce_start + nonce_size];
    let ciphertext = &encrypted[nonce_start + nonce_size..];

    // Decrypt data using ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
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

/// Encrypt data for a specific NEAR account using hybrid encryption
/// Used for internal email sending (NEAR to NEAR)
///
/// Format: HE01 || key_len (2 bytes) || ECIES(symmetric_key) || nonce (12 bytes) || ChaCha20-Poly1305(data)
pub fn encrypt_for_account(
    master_privkey: &SecretKey,
    account_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rand::RngCore;

    let user_pubkey = derive_user_pubkey(master_privkey, account_id)?;

    // Generate random 32-byte symmetric key
    let mut symmetric_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut symmetric_key);

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Encrypt symmetric key with ECIES
    let encrypted_key = ecies::encrypt(&user_pubkey, &symmetric_key)
        .map_err(|e| format!("Failed to encrypt symmetric key: {}", e))?;

    // Encrypt data with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| format!("Failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {:?}", e))?;

    // Build output: magic || key_len || encrypted_key || nonce || ciphertext
    let key_len = encrypted_key.len() as u16;
    let mut output = Vec::with_capacity(4 + 2 + encrypted_key.len() + 12 + ciphertext.len());
    output.extend_from_slice(HYBRID_MAGIC);
    output.extend_from_slice(&key_len.to_le_bytes());
    output.extend_from_slice(&encrypted_key);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}
