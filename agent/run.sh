#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
RULE_SOURCE="${OLOPA_RULE_SOURCE:-$ROOT/oilc/src/rules/mvp_exec.oil}"
RUNTIME_IR_PATH="${OLOPA_RUNTIME_IR:-$ROOT/tmp/runtime-ir.json}"
IFACE="${1:-${OLOPA_IFACE:-lo}}"
PROBE_EVENTS="${OLOPA_PROBE_EVENTS:-fork,exec,file,net}"
OILC_BIN="$ROOT/oilc/target/release/oilc"
AGENT_BIN="$ROOT/agent/target/debug/olopa"

if [[ ! -f "$RULE_SOURCE" ]]; then
  printf 'Rule source not found: %s\n' "$RULE_SOURCE" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$RUNTIME_IR_PATH")"

if [[ ! -x "$OILC_BIN" ]]; then
  cargo build --release --manifest-path "$ROOT/oilc/Cargo.toml"
fi
if [[ ! -x "$AGENT_BIN" ]]; then
  cargo build --manifest-path "$ROOT/agent/Cargo.toml" -p olopa
fi

"$OILC_BIN" \
  --source "$RULE_SOURCE" \
  --emit-runtime-ir "$RUNTIME_IR_PATH" \
  --mode runtime-ir

AGENT_ENV=(
  "RUST_LOG=${RUST_LOG:-info}"
  "OLOPA_RUNTIME_IR=$RUNTIME_IR_PATH"
  "OLOPA_INGEST_URL=${OLOPA_INGEST_URL:-http://127.0.0.1:8000/api/v1/ingest/batches}"
  "OLOPA_INGEST_API_TOKEN=${OLOPA_INGEST_API_TOKEN:-${OLOPA_MVP_INGEST_TOKEN:-olopa-local-ingest}}"
  "OLOPA_INGEST_TENANT_ID=${OLOPA_INGEST_TENANT_ID:-default}"
  "OLOPA_INGEST_HOST_ID=${OLOPA_INGEST_HOST_ID:-$(hostname)}"
  "OLOPA_STATUS_PATH=${OLOPA_STATUS_PATH:-/tmp/olopa/agent/status.json}"
  "OLOPA_SQL_POLICY_ENABLED=${OLOPA_SQL_POLICY_ENABLED:-0}"
  "OLOPA_SQL_POLICY_MODE=${OLOPA_SQL_POLICY_MODE:-observe}"
  "OLOPA_SQL_POLICY_SOCKET=${OLOPA_SQL_POLICY_SOCKET:-/run/olopa/sql-policy.sock}"
)
AGENT_COMMAND=("$AGENT_BIN" --iface "$IFACE" --probe-events "$PROBE_EVENTS")

if (( EUID == 0 )); then
  exec env "${AGENT_ENV[@]}" "${AGENT_COMMAND[@]}"
else
  exec sudo env "${AGENT_ENV[@]}" "${AGENT_COMMAND[@]}"
fi
