#!/bin/bash

set -ex

echo "🧪 Running Enigma Tests"
echo "======================"

RUST_LOG=trace cargo tarpaulin --profile coverage --out Html --test enigma_test -- --nocapture

echo ""
echo "✅ Tests completed!"