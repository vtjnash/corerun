#!/bin/bash

# Build script that compiles the Rust project and applies entitlements to the empty_process binary

set -e

echo "Building corerun project..."
cargo build "$@"

# Apply entitlements to the empty_process binary
BINARY_PATH="target/debug/empty_process"
if [ "$1" = "--release" ]; then
    BINARY_PATH="target/release/empty_process"
fi

if [ -f "$BINARY_PATH" ]; then
    echo "Applying entitlements to $BINARY_PATH..."
    
    # Check if codesign is available
    if command -v codesign &> /dev/null; then
        # Apply the entitlements with ad-hoc signature
        codesign --entitlements entitlements.plist --force --sign - "$BINARY_PATH"
        echo "✓ Entitlements applied successfully"
        
        # Verify the entitlements were applied
        echo "Verifying entitlements:"
        codesign --display --entitlements - "$BINARY_PATH"
    else
        echo "⚠️  codesign not found - skipping entitlements (binary may not work properly)"
    fi
else
    echo "⚠️  Binary not found at $BINARY_PATH - skipping entitlements"
fi

echo "Build complete!"