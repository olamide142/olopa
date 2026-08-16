# Olopa ingest server

The ingest API durably records every accepted batch before acknowledging it, then flushes partitioned queues to SurrealDB, ClickHouse, or local JSONL. Uncommitted WAL records replay after restart and successful sink writes checkpoint and compact the WAL.

Production deployments should set at least:

```text
INGEST_PRODUCTION_MODE=true
INGEST_API_TOKENS=<token>:<tenant>
INGEST_WAL_PATH=/var/lib/olopa/ingest/acceptance.wal
INGEST_DEDUPE_PATH=/var/lib/olopa/ingest/dedupe.json
INGEST_PERSIST_JSONL_PATH=/var/lib/olopa/ingest/events.jsonl
INGEST_DEAD_LETTER_PATH=/var/lib/olopa/ingest/dead-letter.jsonl
INGEST_CORS_ALLOWED_ORIGINS=https://console.example.com
```

Important tuning variables:

- `INGEST_MAX_REQUEST_BODY_BYTES` (default 8 MiB)
- `INGEST_RATE_LIMIT_PER_SECOND` and `INGEST_RATE_LIMIT_BURST`
- `INGEST_QUEUE_MAXSIZE`, `INGEST_FLUSH_WORKERS`, `INGEST_FLUSH_MAX_ROWS`
- `INGEST_WAL_COMPACT_AFTER_COMMITS` and `INGEST_DEDUPE_MAX_ENTRIES`
- `INGEST_SINK_RETRY_MAX_ATTEMPTS`, `INGEST_SINK_RETRY_INITIAL_MS`, `INGEST_SINK_RETRY_MAX_MS`
- `INGEST_CIRCUIT_FAILURE_THRESHOLD` and `INGEST_CIRCUIT_OPEN_MS`

Operational endpoints are `GET /health`, `GET /ready`, and `GET /metrics`. Metrics require a global-scope token when authentication is configured.
