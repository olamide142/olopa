CREATE DATABASE IF NOT EXISTS olopa;

CREATE TABLE IF NOT EXISTS olopa.events_raw
(
    tenant_id String,
    host_id String,
    schema_version UInt32,
    batch_id Nullable(String),
    ingested_at_unix_ms UInt64,
    event_kind LowCardinality(String),
    event JSON
)
ENGINE = MergeTree
ORDER BY (tenant_id, host_id, ingested_at_unix_ms);
