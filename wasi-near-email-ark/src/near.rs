//! NEAR signature verification

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a NEAR signature
///
/// The message should include a timestamp to prevent replay attacks:
/// e.g., "near-email:get_emails:1234567890"
pub fn verify_signature(
    account_id: &str,
    message: &str,
    signature_b64: &str,
    public_key_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check message format and timestamp
    validate_message(message)?;

    // Parse public key (format: "ed25519:base58encoded")
    let pubkey_bytes = parse_near_public_key(public_key_str)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)?;

    // Parse signature (base64 encoded)
    let sig_bytes = base64::decode(signature_b64)?;
    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".into());
    }
    let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());

    // Verify signature
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "Signature verification failed")?;

    // TODO: Verify that public key belongs to account_id
    // This would require querying NEAR RPC to check access keys
    // For now, we trust the signature verification
    let _ = account_id;

    Ok(())
}

/// Parse NEAR public key from string format
/// Supports: "ed25519:base58encoded" or just "base58encoded"
fn parse_near_public_key(public_key_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let key_data = if let Some(stripped) = public_key_str.strip_prefix("ed25519:") {
        stripped
    } else {
        public_key_str
    };

    let bytes = bs58::decode(key_data).into_vec()?;
    if bytes.len() != 32 {
        return Err(format!("Invalid public key length: expected 32, got {}", bytes.len()).into());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Validate message format and timestamp
fn validate_message(message: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Expected format: "near-email:<action>:<timestamp>"
    let parts: Vec<&str> = message.split(':').collect();
    if parts.len() < 3 {
        return Err("Invalid message format".into());
    }

    if parts[0] != "near-email" {
        return Err("Invalid message prefix".into());
    }

    // Parse and validate timestamp
    let timestamp: u64 = parts[parts.len() - 1]
        .parse()
        .map_err(|_| "Invalid timestamp")?;

    // Check timestamp is within 5 minutes
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };

    if diff > 300 {
        return Err("Message timestamp expired (>5 minutes)".into());
    }

    Ok(())
}
