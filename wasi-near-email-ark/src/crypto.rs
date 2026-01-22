//! Cryptographic utilities for near.email WASI module
//!
//! Implements private key derivation and email decryption.

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Domain separation prefix for key derivation
const DERIVATION_PREFIX: &[u8] = b"near-email:v1:";

/// Parse a hex-encoded private key
pub fn parse_private_key(hex_str: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    let privkey = SecretKey::from_slice(&bytes)?;
    Ok(privkey)
}

/// Derive master public key from master private key
/// Returns compressed public key in hex format (33 bytes = 66 hex chars)
pub fn get_master_pubkey(master_privkey: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, master_privkey);
    hex::encode(pubkey.serialize())
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

    // Convert to scalar
    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| "Failed to create scalar from tweak")?;

    // Add tweak to private key (scalar addition)
    let user_privkey = master_privkey
        .add_tweak(&tweak)
        .map_err(|_| "Failed to derive private key")?;

    Ok(user_privkey)
}

/// Decrypt email data using ECIES
pub fn decrypt_email(
    user_privkey: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decrypted = ecies::decrypt(&user_privkey.secret_bytes(), encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(decrypted)
}

/// Derive user's public key from master private key
/// Used for encrypting emails to other NEAR accounts
pub fn derive_user_pubkey(
    master_privkey: &SecretKey,
    account_id: &str,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let user_privkey = derive_user_privkey(master_privkey, account_id)?;
    let secp = Secp256k1::new();
    Ok(PublicKey::from_secret_key(&secp, &user_privkey))
}

/// Encrypt data for a specific NEAR account
/// Used for internal email sending (NEAR to NEAR)
pub fn encrypt_for_account(
    master_privkey: &SecretKey,
    account_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let user_pubkey = derive_user_pubkey(master_privkey, account_id)?;
    let encrypted = ecies::encrypt(&user_pubkey.serialize(), data)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    Ok(encrypted)
}
