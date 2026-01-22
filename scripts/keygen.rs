//! Key generation utility for near.email
//!
//! Generates a master keypair for the email encryption system.
//! Run with: cargo run --bin keygen
//!
//! Or manually:
//!   rustc scripts/keygen.rs -o keygen && ./keygen

use std::process::Command;

fn main() {
    // This is a simple script that uses openssl to generate keys
    // For production, use proper key management

    println!("Generating secp256k1 master keypair for near.email...\n");

    // Generate private key
    let output = Command::new("openssl")
        .args(["ecparam", "-name", "secp256k1", "-genkey", "-noout"])
        .output()
        .expect("Failed to run openssl");

    if !output.status.success() {
        eprintln!("Error generating private key:");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }

    let pem = String::from_utf8_lossy(&output.stdout);
    println!("Private key (PEM format - keep secret!):");
    println!("{}", pem);

    // Extract raw private key bytes
    let output = Command::new("openssl")
        .args(["ec", "-text", "-noout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn openssl")
        .wait_with_output()
        .expect("Failed to wait for openssl");

    println!("\n-------------------------------------------");
    println!("For a real implementation, use a Rust program");
    println!("with secp256k1 crate to generate keys properly.");
    println!("-------------------------------------------\n");

    println!("Example Rust code to generate keys:");
    println!(r#"
use secp256k1::{{SecretKey, PublicKey, Secp256k1}};
use rand::rngs::OsRng;

fn main() {{
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    println!("PROTECTED_MASTER_KEY={{}}", hex::encode(secret_key.secret_bytes()));
    println!("MASTER_PUBLIC_KEY={{}}", hex::encode(public_key.serialize()));
}}
"#);
}
