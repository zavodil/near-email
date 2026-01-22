#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building SMTP server..."
cargo build --release

echo ""
echo "Binary: target/release/smtp-server"
ls -lh ../target/release/smtp-server 2>/dev/null || ls -lh target/release/smtp-server
