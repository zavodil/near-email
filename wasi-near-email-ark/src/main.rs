//! OutLayer WASI module for near.email
//!
//! Decrypts emails for NEAR account owners by:
//! 1. Verifying NEAR signature (prove account ownership)
//! 2. Deriving private key from master key + account_id
//! 3. Fetching encrypted emails from database
//! 4. Decrypting and returning plaintext emails

mod crypto;
mod db;
mod near;
mod types;

use outlayer::env;
use types::*;

fn main() {
    let result = process();

    match result {
        Ok(response) => {
            let _ = env::output_json(&response);
        }
        Err(e) => {
            let error_response = ErrorResponse {
                success: false,
                error: e.to_string(),
            };
            let _ = env::output_json(&error_response);
        }
    }
}

fn process() -> Result<Response, Box<dyn std::error::Error>> {
    // Read input
    let input: Request = env::input_json()?
        .ok_or("No input provided")?;

    // Get master private key from secrets
    let master_privkey_hex = std::env::var("MASTER_PRIVATE_KEY")
        .map_err(|_| "MASTER_PRIVATE_KEY not configured")?;

    let master_privkey = crypto::parse_private_key(&master_privkey_hex)?;

    // Get database API URL
    let db_api_url = std::env::var("DATABASE_API_URL")
        .map_err(|_| "DATABASE_API_URL not configured")?;

    match input {
        Request::GetEmails {
            account_id,
            signature,
            public_key,
            message,
            limit,
            offset,
        } => {
            // Verify NEAR signature
            near::verify_signature(&account_id, &message, &signature, &public_key)?;

            // Derive user's private key
            let user_privkey = crypto::derive_user_privkey(&master_privkey, &account_id)?;

            // Fetch encrypted emails from database
            let encrypted_emails = db::fetch_emails(
                &db_api_url,
                &account_id,
                limit.unwrap_or(50),
                offset.unwrap_or(0),
            )?;

            // Decrypt emails
            let mut emails = Vec::new();
            for enc_email in encrypted_emails {
                match crypto::decrypt_email(&user_privkey, &enc_email.encrypted_data) {
                    Ok(decrypted) => {
                        // Parse email content
                        let parsed = parse_email(&decrypted)?;
                        emails.push(Email {
                            id: enc_email.id,
                            from: enc_email.sender_email,
                            subject: parsed.subject,
                            body: parsed.body,
                            received_at: enc_email.received_at,
                        });
                    }
                    Err(e) => {
                        // Log decryption error but continue with other emails
                        eprintln!("Failed to decrypt email {}: {}", enc_email.id, e);
                    }
                }
            }

            Ok(Response::GetEmails(GetEmailsResponse {
                success: true,
                emails,
            }))
        }

        Request::SendEmail {
            account_id,
            signature,
            public_key,
            message,
            to,
            subject,
            body,
        } => {
            // Verify NEAR signature
            near::verify_signature(&account_id, &message, &signature, &public_key)?;

            // Send email via SMTP relay
            db::send_email(&db_api_url, &account_id, &to, &subject, &body)?;

            Ok(Response::SendEmail(SendEmailResponse {
                success: true,
                message_id: None, // Could be returned from SMTP relay
            }))
        }

        Request::DeleteEmail {
            account_id,
            signature,
            public_key,
            message,
            email_id,
        } => {
            // Verify NEAR signature
            near::verify_signature(&account_id, &message, &signature, &public_key)?;

            // Delete email from database
            let deleted = db::delete_email(&db_api_url, &email_id, &account_id)?;

            Ok(Response::DeleteEmail(DeleteEmailResponse {
                success: true,
                deleted,
            }))
        }

        Request::GetEmailCount {
            account_id,
            signature,
            public_key,
            message,
        } => {
            // Verify NEAR signature
            near::verify_signature(&account_id, &message, &signature, &public_key)?;

            // Get email count
            let count = db::count_emails(&db_api_url, &account_id)?;

            Ok(Response::GetEmailCount(GetEmailCountResponse {
                success: true,
                count,
            }))
        }
    }
}

/// Parse decrypted email content
fn parse_email(data: &[u8]) -> Result<ParsedEmail, Box<dyn std::error::Error>> {
    let parsed = mailparse::parse_mail(data)?;

    let subject = parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("subject"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    let body = parsed.get_body()?;

    Ok(ParsedEmail { subject, body })
}

struct ParsedEmail {
    subject: String,
    body: String,
}
