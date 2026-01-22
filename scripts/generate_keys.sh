#!/bin/bash
# Generate master keypair for near.email
#
# This uses Rust with secp256k1 crate to generate proper keys.
# The keys should be stored securely:
#   - PROTECTED_MASTER_KEY: Only in OutLayer TEE secrets
#   - MASTER_PUBLIC_KEY: In SMTP server .env

set -e

cd "$(dirname "$0")"

# Create a temporary Rust project
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

cat > Cargo.toml << 'EOF'
[package]
name = "keygen"
version = "0.1.0"
edition = "2021"

[dependencies]
secp256k1 = { version = "0.29", features = ["rand"] }
rand = "0.8"
hex = "0.4"
EOF

mkdir -p src
cat > src/main.rs << 'EOF'
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use rand::rngs::OsRng;

fn main() {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    eprintln!("Generated secp256k1 master keypair for near.email");
    eprintln!("================================================");
    eprintln!();
    eprintln!("IMPORTANT: Keep the private key secret!");
    eprintln!("Only store it in OutLayer TEE secrets.");
    eprintln!();

    println!("# Add to OutLayer secrets:");
    println!("PROTECTED_MASTER_KEY={}", hex::encode(secret_key.secret_bytes()));
    println!();
    println!("# Add to smtp-server/.env:");
    println!("MASTER_PUBLIC_KEY={}", hex::encode(public_key.serialize()));
}
EOF

cargo run --release 2>/dev/null

# Cleanup
cd /
rm -rf "$TEMP_DIR"
