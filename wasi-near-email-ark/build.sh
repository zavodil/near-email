#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building WASI module (wasm32-wasip2)..."

# Add target if needed
rustup target add wasm32-wasip2 2>/dev/null || true

# Build
cargo build --target wasm32-wasip2 --release

echo ""
echo "WASM module: target/wasm32-wasip2/release/wasi-near-email-ark.wasm"
ls -lh target/wasm32-wasip2/release/wasi-near-email-ark.wasm
