#!/bin/bash
set -e

cd "$(dirname "$0")"

WASM_FILE="target/wasm32-wasip2/release/wasi-near-email-ark.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

echo "Building WASI module (wasm32-wasip2)..."

# Add target if needed
rustup target add wasm32-wasip2 2>/dev/null || true

# Build
cargo build --target wasm32-wasip2 --release

echo ""

# Note: wasm-opt doesn't support WASI P2 components yet
# https://github.com/WebAssembly/binaryen/issues/6728

# Show file size
SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE" 2>/dev/null)
SIZE_MB=$(echo "scale=2; $SIZE / 1024 / 1024" | bc)
SIZE_KB=$(echo "scale=0; $SIZE / 1024" | bc)

echo "WASM module: $WASM_FILE"
echo "Size: ${SIZE_KB} KB (${SIZE_MB} MB)"

# Warning if over 2MB
if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo ""
    echo "WARNING: File size exceeds 2MB limit for FastFS upload!"
    echo "Current: ${SIZE_MB} MB, Limit: 2.00 MB"
    echo ""
    echo "Tips to reduce size:"
    echo "  - Install wasm-opt: brew install binaryen"
    echo "  - Check for unused dependencies in Cargo.toml"
    echo "  - Use 'cargo bloat' to find largest functions"
else
    echo "OK: Size is within 2MB limit for FastFS"
fi
