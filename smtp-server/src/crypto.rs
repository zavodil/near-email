//! Cryptographic utilities for near.email
//!
//! Implements BIP32-style public key derivation that allows deriving
//! user-specific public keys without knowing the master private key.

use anyhow::{anyhow, Result};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

/// Domain separation prefix for key derivation
const DERIVATION_PREFIX: &[u8] = b"near-email:v1:";

/// Parse a hex-encoded compressed public key
pub fn parse_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("Invalid hex: {}", e))?;
    PublicKey::from_slice(&bytes)
        .map_err(|e| anyhow!("Invalid public key: {}", e))
}

/// Derive a user-specific public key from master public key
///
/// Uses additive key derivation:
///   user_pubkey = master_pubkey + SHA256(prefix + account_id) * G
///
/// This allows the SMTP server to encrypt emails without knowing
/// the master private key.
pub fn derive_user_pubkey(master_pubkey: &PublicKey, account_id: &str) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    // Create deterministic tweak from account_id
    let mut hasher = Sha256::new();
    hasher.update(DERIVATION_PREFIX);
    hasher.update(account_id.as_bytes());
    let tweak_bytes: [u8; 32] = hasher.finalize().into();

    // Convert to scalar (may fail if hash > curve order, extremely unlikely)
    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| anyhow!("Failed to create scalar from tweak"))?;

    // Add tweak to public key (EC point addition: P' = P + t*G)
    master_pubkey
        .add_exp_tweak(&secp, &tweak)
        .map_err(|e| anyhow!("Failed to derive public key: {}", e))
}

/// Encrypt data using ECIES with the derived public key
pub fn encrypt_for_account(
    master_pubkey: &PublicKey,
    account_id: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    // Derive user's public key
    let user_pubkey = derive_user_pubkey(master_pubkey, account_id)?;

    // Encrypt using ECIES
    let encrypted = ecies::encrypt(&user_pubkey.serialize(), data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    #[test]
    fn test_key_derivation_consistency() {
        let secp = Secp256k1::new();

        // Generate master keypair
        let master_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let master_pubkey = PublicKey::from_secret_key(&secp, &master_privkey);

        // Derive public key twice - should be identical
        let derived1 = derive_user_pubkey(&master_pubkey, "alice.near").unwrap();
        let derived2 = derive_user_pubkey(&master_pubkey, "alice.near").unwrap();

        assert_eq!(derived1, derived2);

        // Different accounts should have different keys
        let derived_bob = derive_user_pubkey(&master_pubkey, "bob.near").unwrap();
        assert_ne!(derived1, derived_bob);
    }

    #[test]
    fn test_encryption_decryption() {
        let secp = Secp256k1::new();

        // Generate master keypair
        let master_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let master_pubkey = PublicKey::from_secret_key(&secp, &master_privkey);

        // Encrypt for alice.near
        let plaintext = b"Hello, Alice!";
        let encrypted = encrypt_for_account(&master_pubkey, "alice.near", plaintext).unwrap();

        // To decrypt, we need the derived private key
        // (This would happen in OutLayer TEE)
        let mut hasher = Sha256::new();
        hasher.update(DERIVATION_PREFIX);
        hasher.update(b"alice.near");
        let tweak_bytes: [u8; 32] = hasher.finalize().into();
        let tweak = Scalar::from_be_bytes(tweak_bytes).unwrap();

        let user_privkey = master_privkey.add_tweak(&tweak).unwrap();

        // Decrypt
        let decrypted = ecies::decrypt(&user_privkey.secret_bytes(), &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
