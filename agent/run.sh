#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/olamide/dev/olopa"
# RULE_SOURCE="$ROOT/oilc/src/rules/stress_test/rule_a.oil"
RULE_SOURCE="/home/olamide/dev/olopa/oilc/src/rules/showcase.oil"
RUNTIME_IR_DIR="$ROOT/tmp"
RUNTIME_IR_PATH="$RUNTIME_IR_DIR/runtime-ir.json"
IFACE="${1:-lo}"

mkdir -p "$RUNTIME_IR_DIR"

cargo run --manifest-path "$ROOT/oilc/Cargo.toml" -- \
  --source "$RULE_SOURCE" \
  --emit-runtime-ir "$RUNTIME_IR_PATH" \
  --mode check

sudo -E OLOPA_RUNTIME_IR="$RUNTIME_IR_PATH" RUST_LOG=info \
  cargo run --manifest-path "$ROOT/agent/Cargo.toml" -p olopa-agent -- --iface "$IFACE"
