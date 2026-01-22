//! Cryptographic utilities for near.email WASI module
//!
//! Implements private key derivation and email decryption.

use secp256k1::{Scalar, SecretKey};
use sha2::{Digest, Sha256};

/// Domain separation prefix for key derivation
const DERIVATION_PREFIX: &[u8] = b"near-email:v1:";

/// Parse a hex-encoded private key
pub fn parse_private_key(hex_str: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    let privkey = SecretKey::from_slice(&bytes)?;
    Ok(privkey)
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
